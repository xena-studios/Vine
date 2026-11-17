use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::config::{CConfigDisconnect, CFinishConfig};
use pumpkin_protocol::java::client::login::{
    CLoginDisconnect, CLoginPluginRequest, CLoginSuccess, CSetCompression,
};
use pumpkin_protocol::java::client::play::{
    ArgumentType, CActionBar, CCommandSuggestions, CCommands, CPlayDisconnect, CStartConfiguration,
    CSubtitle, CSystemChatMessage, CTitleAnimation, CTitleText, CTransfer, ProtoNode,
    ProtoNodeType, StringProtoArgBehavior, SuggestionProviders,
};
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::{
    SLoginAcknowledged, SLoginPluginResponse, SLoginStart,
};
use pumpkin_protocol::java::server::play::{
    SChatCommand, SChatCommandSigned, SChatMessage, SCommandSuggestion, SConfigurationAcknowledged,
    SCustomPayload,
};
use pumpkin_protocol::ser::{NetworkReadExt, NetworkReadSliceExt};
use pumpkin_protocol::{ConnectionState, ServerPacket};
use pumpkin_util::text::TextComponent;
use pumpkin_util::version::JavaMinecraftVersion;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::AuthenticatedPlayer;
use crate::backend::forwarding::{
    ForwardingHelper, VELOCITY_PLAYER_INFO_CHANNEL, VINE_PLAYER_INFO_CHANNEL,
};
use crate::command::{CommandDispatcher, CommandSender, ProxyCommandSource};
use crate::config::{BackendConfig, Config, ForwardingMode, NetworkConfig};
use crate::legacy;
use crate::network;
use crate::plugin::PluginManager;
use crate::plugin::api::{
    PlayerChatEvent, PlayerCommandEvent, PlayerDisconnectEvent, PlayerJoinEvent,
    PluginMessageEvent, ServerConnectEvent, ServerConnectedEvent, ServerKickEvent,
};
use crate::protocol::{self, VersionedPacket};
use crate::security::PacketRateLimiter;
use crate::session::{PlayerAction, PlayerSession, SessionManager};

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Failed to connect to backend server '{0}': {1}")]
    ConnectFailed(String, std::io::Error),
    #[error("Backend communication error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Packet decode error: {0}")]
    DecodeError(String),
    #[error("Packet encode error: {0}")]
    EncodeError(String),
    #[error("Backend server '{0}' login timed out")]
    LoginTimeout(String),
    #[error("Backend disconnected player during login: {0}")]
    LoginDisconnected(String),
    #[error("Velocity forwarding error: {0}")]
    VelocityError(String),
    #[error("Vine forwarding error: {0}")]
    VineError(String),
    #[error("Client went away: {0}")]
    ClientGone(String),
}

type BackendRead = TCPNetworkDecoder<tokio::net::tcp::OwnedReadHalf>;
type BackendWrite = TCPNetworkEncoder<tokio::net::tcp::OwnedWriteHalf>;

#[derive(Debug)]
pub enum TunnelExit {
    /// Client disconnected or connection closed
    ClientDisconnected,
    /// Player requested switch to another backend server
    Connect { server_name: String },
    /// Direct client transfer requested
    Transfer { host: String, port: u16 },
    /// Backend server closed connection or sent disconnect/kick
    BackendDisconnected { reason: Option<String> },
    /// A plugin disconnected the player (`disconnect-player`): a real disconnect, no fallback
    Disconnect { reason: String },
}

pub struct BackendBridge {
    server_name: String,
    config: BackendConfig,
    client_ip: IpAddr,
    client_version: JavaMinecraftVersion,
    /// The version backends see: the current one when Vine translates for the client.
    backend_version: JavaMinecraftVersion,
    virtual_host: String,
    player: AuthenticatedPlayer,
    max_packets_per_sec: u32,
    online_players: Arc<AtomicUsize>,
    network_config: Arc<NetworkConfig>,
    compression_level: i32,
    session_manager: Arc<SessionManager>,
    command_dispatcher: Arc<CommandDispatcher>,
    proxy_config: Arc<Config>,
    plugin_manager: Arc<PluginManager>,
}

impl BackendBridge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_name: String,
        config: BackendConfig,
        client_ip: IpAddr,
        client_version: JavaMinecraftVersion,
        virtual_host: String,
        player: AuthenticatedPlayer,
        max_packets_per_sec: u32,
        online_players: Arc<AtomicUsize>,
        network_config: Arc<NetworkConfig>,
        compression_level: i32,
        session_manager: Arc<SessionManager>,
        command_dispatcher: Arc<CommandDispatcher>,
        proxy_config: Arc<Config>,
        plugin_manager: Arc<PluginManager>,
    ) -> Self {
        Self {
            server_name,
            config,
            client_ip,
            client_version,
            backend_version: legacy::backend_version(client_version),
            virtual_host,
            player,
            max_packets_per_sec,
            online_players,
            network_config,
            compression_level,
            session_manager,
            command_dispatcher,
            proxy_config,
            plugin_manager,
        }
    }

    /// Establishes connection to backend with retry attempts and timeout
    async fn connect_to_backend(
        server_name: &str,
        address: &str,
        timeout_secs: u64,
        retries: u32,
    ) -> Result<TcpStream, BridgeError> {
        let connect_timeout = Duration::from_secs(timeout_secs);
        let mut last_err = None;

        for attempt in 1..=retries.max(1) {
            match timeout(connect_timeout, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    debug!(
                        "Connection attempt {}/{} to '{}' ({}) failed: {}",
                        attempt, retries, server_name, address, e
                    );
                    last_err = Some(e);
                }
                Err(_) => {
                    debug!(
                        "Connection attempt {}/{} to '{}' ({}) timed out after {}s",
                        attempt, retries, server_name, address, timeout_secs
                    );
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("Connection timed out after {}s", timeout_secs),
                    ));
                }
            }

            if attempt < retries {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }

        Err(BridgeError::ConnectFailed(
            server_name.to_string(),
            last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "Failed to connect")
            }),
        ))
    }

    /// Connects to a backend server, configures the socket, and executes the login sequence
    async fn login_backend(
        &self,
        server_name: &str,
        active_config: &BackendConfig,
    ) -> Result<
        (
            TCPNetworkDecoder<tokio::net::tcp::OwnedReadHalf>,
            TCPNetworkEncoder<tokio::net::tcp::OwnedWriteHalf>,
            Vec<u8>,
        ),
        BridgeError,
    > {
        let backend_stream = Self::connect_to_backend(
            server_name,
            &active_config.address,
            self.network_config.backend_connect_timeout_secs,
            self.network_config.backend_connect_retry_attempts,
        )
        .await?;

        if let Err(e) = network::configure_backend_socket(&backend_stream, &self.network_config) {
            debug!("Failed to configure backend socket: {}", e);
        }

        let (backend_read, backend_write) = backend_stream.into_split();
        let mut backend_decoder = TCPNetworkDecoder::new(backend_read);
        let mut backend_encoder = TCPNetworkEncoder::new(backend_write);

        let backend_host = match active_config.forwarding {
            ForwardingMode::BungeeCord => ForwardingHelper::build_bungeecord_host(
                &self.virtual_host,
                &self.client_ip,
                &self.player,
            ),
            ForwardingMode::Velocity | ForwardingMode::Vine | ForwardingMode::None => {
                self.virtual_host.clone()
            }
        };

        let handshake_packet = SHandShake {
            protocol_version: VarInt(self.backend_version.protocol_version()),
            server_address: backend_host.into_boxed_str(),
            server_port: 25565,
            next_state: ConnectionState::Login,
        };

        let handshake_bytes = handshake_packet
            .serialize_for_server(ConnectionState::HandShake, self.backend_version)
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .write_packet(handshake_bytes)
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;

        let login_start_packet = SLoginStart {
            name: self.player.username.clone().into_boxed_str(),
            uuid: self.player.id,
        };
        let login_start_bytes = login_start_packet
            .serialize_for_server(ConnectionState::Login, self.backend_version)
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .write_packet(login_start_bytes)
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        backend_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;

        let login_timeout_dur = Duration::from_secs(self.network_config.backend_login_timeout_secs);
        // The backend speaks `backend_version`, so its ids are that version's.
        let login_disconnect_id = protocol::clientbound_id::<CLoginDisconnect>(
            ConnectionState::Login,
            self.backend_version,
        );
        let login_plugin_request_id = protocol::clientbound_id::<CLoginPluginRequest>(
            ConnectionState::Login,
            self.backend_version,
        );
        let login_compression_id = protocol::clientbound_id::<CSetCompression>(
            ConnectionState::Login,
            self.backend_version,
        );
        let login_success_id =
            protocol::clientbound_id::<CLoginSuccess>(ConnectionState::Login, self.backend_version);

        loop {
            let raw_packet = timeout(login_timeout_dur, backend_decoder.get_raw_packet())
                .await
                .map_err(|_| BridgeError::LoginTimeout(server_name.to_string()))?
                .map_err(|e| BridgeError::DecodeError(e.to_string()))?;

            if Some(raw_packet.id) == login_disconnect_id {
                let mut cur = &raw_packet.payload[..];
                let reason = cur
                    .get_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "Disconnected by backend during login".to_string());
                warn!(
                    "Backend '{}' disconnected '{}' during login: {}",
                    server_name, self.player.username, reason
                );
                return Err(BridgeError::LoginDisconnected(reason));
            } else if Some(raw_packet.id) == login_plugin_request_id {
                let mut cur = &raw_packet.payload[..];
                let message_id = cur
                    .get_var_int()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?;
                let channel = cur
                    .get_str()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?;

                debug!(
                    "Backend requested login plugin message on channel '{}'",
                    channel
                );

                if channel.as_ref() == VINE_PLAYER_INFO_CHANNEL {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VineError("Secret missing".to_string()))?;

                    let mut challenge = [0u8; 16];
                    if cur.len() >= 17 {
                        challenge.copy_from_slice(&cur[1..17]);
                    } else if cur.len() >= 16 {
                        challenge.copy_from_slice(&cur[0..16]);
                    }

                    let vine_data = ForwardingHelper::build_vine_payload(
                        secret,
                        &self.client_ip,
                        &self.player,
                        &challenge,
                    )
                    .map_err(|e| BridgeError::VineError(e.to_string()))?;

                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: Some(vine_data.into_boxed_slice()),
                    };

                    let resp_bytes = plugin_response
                        .serialize_for_server(ConnectionState::Login, self.backend_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                } else if channel.as_ref() == VELOCITY_PLAYER_INFO_CHANNEL {
                    let secret = active_config
                        .secret
                        .as_deref()
                        .ok_or_else(|| BridgeError::VelocityError("Secret missing".to_string()))?;

                    let velocity_data = ForwardingHelper::build_velocity_payload(
                        secret,
                        &self.client_ip,
                        &self.player,
                    )
                    .map_err(|e| BridgeError::VelocityError(e.to_string()))?;

                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: Some(velocity_data.into_boxed_slice()),
                    };

                    let resp_bytes = plugin_response
                        .serialize_for_server(ConnectionState::Login, self.backend_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                } else {
                    let plugin_response = SLoginPluginResponse {
                        message_id,
                        data: None,
                    };
                    let resp_bytes = plugin_response
                        .serialize_for_server(ConnectionState::Login, self.backend_version)
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .write_packet(resp_bytes)
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                    backend_encoder
                        .flush()
                        .await
                        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
                }
            } else if Some(raw_packet.id) == login_compression_id {
                let mut cur = &raw_packet.payload[..];
                let threshold = cur
                    .get_var_int()
                    .map_err(|e| BridgeError::DecodeError(e.to_string()))?
                    .0;
                debug!("Backend enabled compression threshold: {} bytes", threshold);
                if threshold >= 0 {
                    backend_decoder.set_compression(threshold as usize);
                    backend_encoder
                        .set_compression((threshold as usize, self.compression_level as u32));
                }
            } else if Some(raw_packet.id) == login_success_id {
                debug!(
                    "Login successful on backend for '{}'!",
                    self.player.username
                );

                let mut full_packet = Vec::with_capacity(5 + raw_packet.payload.len());
                let _ = VarInt(raw_packet.id).encode(&mut full_packet);
                full_packet.extend_from_slice(&raw_packet.payload);
                // A translated client without configuration is in play as soon as it has Login
                // Success, so Vine takes the backend through configuration itself.
                if legacy::translates(self.client_version)
                    && self.client_version < JavaMinecraftVersion::V_1_20_2
                {
                    legacy::configure_backend(
                        &mut backend_decoder,
                        &mut backend_encoder,
                        login_timeout_dur,
                    )
                    .await
                    .map_err(BridgeError::LoginDisconnected)?;
                }
                return Ok((backend_decoder, backend_encoder, full_packet));
            } else {
                debug!(
                    "Unhandled packet during login (ID: {}), skipping",
                    raw_packet.id
                );
            }
        }
    }

    /// Moves the client into the configuration state for a backend it is switching to.
    /// See [`reenter_configuration`].
    async fn reenter_configuration<R, W, B>(
        &self,
        legacy: Option<&legacy::Session>,
        server_name: &str,
        client_decoder: &mut TCPNetworkDecoder<R>,
        client_encoder: &mut TCPNetworkEncoder<W>,
        backend_encoder: &mut TCPNetworkEncoder<B>,
        in_config: &AtomicBool,
    ) -> Result<(), BridgeError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        B: AsyncWrite + Unpin,
    {
        if let Some(session) = legacy
            && self.client_version < JavaMinecraftVersion::V_1_20_2
        {
            session.begin_switch();
        }
        reenter_configuration(
            self.client_version,
            self.backend_version,
            Duration::from_secs(self.network_config.backend_login_timeout_secs),
            &self.player.username,
            server_name,
            client_decoder,
            client_encoder,
            backend_encoder,
            in_config,
        )
        .await?;
        if let Some(session) = legacy {
            session.reset(ConnectionState::Config);
        }
        Ok(())
    }

    /// Fires `server-kick` for a player who lost `lost` and returns the plugins' answer.
    async fn kick_event(
        &self,
        lost: &str,
        reason: Option<String>,
        initial: bool,
    ) -> ServerKickEvent {
        let mut event = ServerKickEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            server_name: lost.to_string(),
            reason,
            initial,
            fallback_server: None,
            message: None,
        };
        self.plugin_manager.fire_server_kick(&mut event).await;
        event
    }

    /// Where a player who lost `lost` may go, in order: see [`fallback_order`].
    fn candidates(&self, event: &ServerKickEvent, lost: &str) -> Vec<String> {
        let servers = &self.proxy_config.servers;
        let configured = if self.proxy_config.routing.try_fallback_on_connect_failure {
            self.proxy_config.routing.fallback_server.as_deref()
        } else {
            None
        };
        fallback_order(
            event.fallback_server.as_deref(),
            configured,
            servers.limbo().as_deref(),
            lost,
            |name| servers.contains_key(name),
        )
    }

    /// Moves a player who lost their backend (`lost`) to the first candidate that takes them.
    /// The client is in play, or already in configuration if `in_config` is set. Returns the
    /// new backend, its name and what to tell the player, or `None` if nothing took them or
    /// the client went away.
    #[allow(clippy::type_complexity)]
    async fn fall_back<R, W>(
        &self,
        lost: &str,
        reason: Option<String>,
        legacy: Option<&legacy::Session>,
        client_decoder: &mut TCPNetworkDecoder<R>,
        client_encoder: &mut TCPNetworkEncoder<W>,
        in_config: &AtomicBool,
    ) -> Option<(BackendRead, BackendWrite, String, String)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let event = self.kick_event(lost, reason.clone(), false).await;
        for candidate in self.candidates(&event, lost) {
            let Some(cfg) = self.proxy_config.servers.get(&candidate) else {
                continue;
            };
            info!(
                "Moving player '{}' to '{}' after losing '{}' ({})",
                self.player.username,
                candidate,
                lost,
                reason.as_deref().unwrap_or("connection closed")
            );
            let (dec, mut enc, _) = match self.login_backend(&candidate, &cfg).await {
                Ok(backend) => backend,
                Err(e) => {
                    warn!(
                        "Fallback '{}' for player '{}' failed: {}",
                        candidate, self.player.username, e
                    );
                    continue;
                }
            };
            let entered = if in_config.load(Ordering::Acquire) {
                acknowledge_login(self.backend_version, &mut enc)
                    .await
                    .map(|()| {
                        if let Some(session) = legacy {
                            session.reset(ConnectionState::Config);
                        }
                    })
            } else {
                self.reenter_configuration(
                    legacy,
                    &candidate,
                    client_decoder,
                    client_encoder,
                    &mut enc,
                    in_config,
                )
                .await
            };
            match entered {
                Ok(()) => {
                    let notice = event
                        .message
                        .clone()
                        .unwrap_or_else(|| moved_notice(lost, reason.as_deref(), &candidate));
                    return Some((dec, enc, candidate, notice));
                }
                Err(BridgeError::ClientGone(e)) => {
                    debug!(
                        "Player '{}' left while moving to '{}': {}",
                        self.player.username, candidate, e
                    );
                    return None;
                }
                Err(e) => warn!(
                    "Player '{}' did not finish moving to '{}': {}",
                    self.player.username, candidate, e
                ),
            }
        }
        None
    }

    /// Establishes connection to backend, handles login handshake, and tunnels packets
    ///
    /// Returns `Err` only if the player never reached a backend. Once they have, every
    /// exit goes through the end of this function, which fires `player-disconnect`.
    ///
    /// Vine never disconnects a player because of a backend: a kick, a crash, a closed
    /// connection or a backend it can't reach moves them to the server plugins pick in
    /// `server-kick`, then `routing.fallback_server`, then the built-in limbo. Only the
    /// client leaving, a plugin's `disconnect-player`, or nothing at all taking them ends
    /// the connection.
    pub async fn run<R, W>(
        self,
        mut client_decoder: TCPNetworkDecoder<R>,
        mut client_encoder: TCPNetworkEncoder<W>,
    ) -> Result<(), BridgeError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        info!(
            "Connecting player '{}' ({}) to backend server '{}' at {}",
            self.player.username, self.player.id, self.server_name, self.config.address
        );

        let mut connect_event = ServerConnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            current_server: None,
            target_server: self.server_name.clone(),
            cancelled: false,
            cancel_reason: None,
        };
        self.plugin_manager
            .fire_server_connect(&mut connect_event)
            .await;
        if connect_event.cancelled {
            let reason = connect_event
                .cancel_reason
                .unwrap_or_else(|| "Connection cancelled by plugin".to_string());
            warn!(
                "Player '{}' connection to '{}' cancelled by plugin: {}",
                self.player.username, connect_event.target_server, reason
            );
            return Err(BridgeError::VineError(reason));
        }
        let target = connect_event.target_server;
        let mut pending_notice: Option<String> = None;

        // The first backend. The client is still in the login state, so any candidate can
        // take it from here.
        let first = match self.proxy_config.servers.get(&target) {
            Some(cfg) => self
                .login_backend(&target, &cfg)
                .await
                .map_err(|e| e.to_string()),
            None if target == self.server_name => self
                .login_backend(&target, &self.config)
                .await
                .map_err(|e| e.to_string()),
            None => Err(format!("server '{target}' isn't registered")),
        };
        let (mut current_server_name, (mut backend_decoder, mut backend_encoder, success_bytes)) =
            match first {
                Ok(backend) => (target.clone(), backend),
                Err(err) => {
                    warn!(
                        "Player '{}' couldn't reach '{}': {}",
                        self.player.username, target, err
                    );
                    let event = self.kick_event(&target, Some(err.clone()), true).await;
                    let mut found = None;
                    for candidate in self.candidates(&event, &target) {
                        let Some(cfg) = self.proxy_config.servers.get(&candidate) else {
                            continue;
                        };
                        match self.login_backend(&candidate, &cfg).await {
                            Ok(backend) => {
                                found = Some((candidate, backend));
                                break;
                            }
                            Err(e) => warn!(
                                "Fallback '{}' for player '{}' failed: {}",
                                candidate, self.player.username, e
                            ),
                        }
                    }
                    let Some((name, backend)) = found else {
                        return Err(BridgeError::VineError(format!(
                            "No server could take the player: {err}"
                        )));
                    };
                    let notice = event
                        .message
                        .clone()
                        .unwrap_or_else(|| unreachable_notice(&target, &name));
                    pending_notice = Some(notice);
                    (name, backend)
                }
            };

        // Forward login success packet to the client
        let legacy = legacy::Session::new(self.client_version, self.player.id);
        let success_bytes: Bytes = match &legacy {
            Some(session) => {
                session.reset(ConnectionState::Login);
                session.login_success(&success_bytes).ok_or_else(|| {
                    BridgeError::EncodeError("Login Success for an old client".to_string())
                })?
            }
            None => success_bytes.into(),
        };
        client_encoder
            .write_packet(success_bytes)
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        client_encoder
            .flush()
            .await
            .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
        // 1.20.2+ clients go on to configuration after Login Success.
        let in_config = AtomicBool::new(self.client_version >= JavaMinecraftVersion::V_1_20_2);

        self.online_players.fetch_add(1, Ordering::Relaxed);
        info!(
            "Player '{}' is now connected to backend '{}'! Online players: {}",
            self.player.username,
            current_server_name,
            self.online_players.load(Ordering::Relaxed)
        );

        let connected_event = ServerConnectedEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            server_name: current_server_name.clone(),
        };
        self.plugin_manager
            .fire_server_connected(&connected_event)
            .await;

        let join_event = PlayerJoinEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            client_ip: self.client_ip.to_string(),
            initial_server: current_server_name.clone(),
        };
        self.plugin_manager.fire_player_join(&join_event).await;

        let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel();
        self.session_manager.register(PlayerSession {
            username: self.player.username.clone(),
            uuid: self.player.id,
            current_server: current_server_name.clone(),
            action_tx: action_tx.clone(),
            client_ip: self.client_ip.to_string(),
            protocol_version: self.client_version.protocol_version() as u32,
        });
        if let Some(notice) = pending_notice.take() {
            let _ = action_tx.send(PlayerAction::Message(TextComponent::from_legacy_string(
                &notice,
            )));
        }

        loop {
            let tunnel_res = Self::bridge_tunnel(
                &self.player.username,
                &mut client_decoder,
                &mut client_encoder,
                &mut backend_decoder,
                &mut backend_encoder,
                self.max_packets_per_sec,
                self.client_version,
                legacy.as_deref(),
                &mut action_rx,
                &action_tx,
                self.command_dispatcher.clone(),
                self.proxy_config.clone(),
                self.session_manager.clone(),
                self.plugin_manager.clone(),
                self.player.id,
                current_server_name.clone(),
                &in_config,
            )
            .await;

            let exit = match tunnel_res {
                Ok(exit) => exit,
                Err(e) => {
                    warn!(
                        "Bridge tunnel error for player '{}': {}",
                        self.player.username, e
                    );
                    TunnelExit::BackendDisconnected {
                        reason: Some(e.to_string()),
                    }
                }
            };

            // Where the player is moved after losing their backend (or a switch that
            // failed half way): `(lost, reason)`.
            let lost = match exit {
                TunnelExit::ClientDisconnected => {
                    debug!(
                        "Player '{}' disconnected from client side",
                        self.player.username
                    );
                    break;
                }
                TunnelExit::Disconnect { reason } => {
                    info!(
                        "Disconnecting player '{}': {}",
                        self.player.username, reason
                    );
                    Self::disconnect_client(
                        &mut client_encoder,
                        self.client_version,
                        in_config.load(Ordering::Acquire),
                        &reason,
                    )
                    .await;
                    break;
                }
                TunnelExit::Transfer { host, port } => {
                    let transfer = CTransfer::new(&host, VarInt(port as i32));
                    let state = if in_config.load(Ordering::Acquire) {
                        ConnectionState::Config
                    } else {
                        ConnectionState::Play
                    };
                    if let Ok(bytes) = transfer.serialize_for_client(state, self.client_version) {
                        let _ = client_encoder.write_packet(bytes).await;
                        let _ = client_encoder.flush().await;
                    }
                    info!(
                        "Transferring player '{}' to {}:{}",
                        self.player.username, host, port
                    );
                    break;
                }
                TunnelExit::Connect { server_name } => {
                    info!(
                        "Switching player '{}' to backend server '{}'...",
                        self.player.username, server_name
                    );

                    let mut connect_event = ServerConnectEvent {
                        uuid: self.player.id.to_string(),
                        username: self.player.username.clone(),
                        current_server: Some(current_server_name.clone()),
                        target_server: server_name.clone(),
                        cancelled: false,
                        cancel_reason: None,
                    };
                    self.plugin_manager
                        .fire_server_connect(&mut connect_event)
                        .await;
                    if connect_event.cancelled {
                        let reason = connect_event
                            .cancel_reason
                            .as_deref()
                            .unwrap_or("Server switch cancelled by plugin");
                        let _ = action_tx.send(PlayerAction::Message(
                            TextComponent::from_legacy_string(&format!("§c{reason}")),
                        ));
                        continue;
                    }
                    let server_name = connect_event.target_server;

                    let Some(target_config) = self.proxy_config.servers.get(&server_name) else {
                        let _ = action_tx.send(PlayerAction::Message(TextComponent::text(
                            format!("Server '{}' does not exist.", server_name),
                        )));
                        continue;
                    };

                    match self.login_backend(&server_name, &target_config).await {
                        Ok((new_dec, mut new_enc, _)) => {
                            match self
                                .reenter_configuration(
                                    legacy.as_deref(),
                                    &server_name,
                                    &mut client_decoder,
                                    &mut client_encoder,
                                    &mut new_enc,
                                    &in_config,
                                )
                                .await
                            {
                                Ok(()) => {
                                    backend_decoder = new_dec;
                                    backend_encoder = new_enc;
                                    current_server_name = server_name.clone();
                                    self.session_manager
                                        .update_server(&self.player.username, &current_server_name);
                                    info!(
                                        "Player '{}' successfully switched to '{}'",
                                        self.player.username, current_server_name
                                    );
                                    let connected_event = ServerConnectedEvent {
                                        uuid: self.player.id.to_string(),
                                        username: self.player.username.clone(),
                                        server_name: current_server_name.clone(),
                                    };
                                    self.plugin_manager
                                        .fire_server_connected(&connected_event)
                                        .await;
                                    continue;
                                }
                                Err(BridgeError::ClientGone(e)) => {
                                    debug!(
                                        "Player '{}' left while switching to '{}': {}",
                                        self.player.username, server_name, e
                                    );
                                    break;
                                }
                                // The client already left its old server: move it on.
                                Err(e) => {
                                    warn!(
                                        "Player '{}' did not finish switching to '{}': {}",
                                        self.player.username, server_name, e
                                    );
                                    (server_name, Some(e.to_string()))
                                }
                            }
                        }
                        Err(e) => {
                            // The client is still on its old server: it stays there.
                            warn!(
                                "Failed to switch player '{}' to '{}': {}",
                                self.player.username, server_name, e
                            );
                            let _ = action_tx.send(PlayerAction::Message(TextComponent::text(
                                format!("§cFailed to connect to server '{}': {}", server_name, e),
                            )));
                            continue;
                        }
                    }
                }
                TunnelExit::BackendDisconnected { reason } => {
                    warn!(
                        "Backend server '{}' disconnected player '{}': {:?}",
                        current_server_name, self.player.username, reason
                    );
                    (current_server_name.clone(), reason)
                }
            };

            let (lost, reason) = lost;
            match self
                .fall_back(
                    &lost,
                    reason.clone(),
                    legacy.as_deref(),
                    &mut client_decoder,
                    &mut client_encoder,
                    &in_config,
                )
                .await
            {
                Some((new_dec, new_enc, name, notice)) => {
                    backend_decoder = new_dec;
                    backend_encoder = new_enc;
                    current_server_name = name;
                    self.session_manager
                        .update_server(&self.player.username, &current_server_name);
                    info!(
                        "Player '{}' moved to '{}' after losing '{}'",
                        self.player.username, current_server_name, lost
                    );
                    let connected_event = ServerConnectedEvent {
                        uuid: self.player.id.to_string(),
                        username: self.player.username.clone(),
                        server_name: current_server_name.clone(),
                    };
                    self.plugin_manager
                        .fire_server_connected(&connected_event)
                        .await;
                    let _ = action_tx.send(PlayerAction::Message(
                        TextComponent::from_legacy_string(&notice),
                    ));
                }
                None => {
                    let reason = format!(
                        "Lost connection to '{}' and no other server could take you: {}",
                        lost,
                        reason.as_deref().unwrap_or("connection closed")
                    );
                    Self::disconnect_client(
                        &mut client_encoder,
                        self.client_version,
                        in_config.load(Ordering::Acquire),
                        &reason,
                    )
                    .await;
                    break;
                }
            }
        }

        let disconnect_event = PlayerDisconnectEvent {
            uuid: self.player.id.to_string(),
            username: self.player.username.clone(),
            last_server: Some(current_server_name.clone()),
        };
        self.plugin_manager
            .fire_player_disconnect(&disconnect_event)
            .await;

        self.session_manager.unregister(&self.player.username);
        self.online_players.fetch_sub(1, Ordering::Relaxed);
        info!(
            "Player '{}' disconnected from proxy. Online players: {}",
            self.player.username,
            self.online_players.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Helper to send formatted disconnect packet to client in either play or configuration state
    async fn disconnect_client<W: AsyncWrite + Unpin>(
        encoder: &mut TCPNetworkEncoder<W>,
        version: JavaMinecraftVersion,
        is_config_state: bool,
        reason: &str,
    ) {
        if is_config_state {
            let json_reason = format!(
                r#"{{"text":"[Vine Proxy] {}","color":"red"}}"#,
                reason.replace('"', "\\\"")
            );
            let pkt = CConfigDisconnect::new(&json_reason);
            if let Ok(bytes) = pkt.serialize_for_client(ConnectionState::Config, version) {
                let _ = encoder.write_packet(bytes).await;
                let _ = encoder.flush().await;
            }
        } else {
            let kick_reason = TextComponent::text(reason.to_string());
            let pkt = CPlayDisconnect::new(&kick_reason);
            if let Ok(bytes) = pkt.serialize_for_client(ConnectionState::Play, version) {
                let _ = encoder.write_packet(bytes).await;
                let _ = encoder.flush().await;
            }
        }
    }
}

/// The data of a plugin message a client sent. On 1.7 it starts with its length as an i16,
/// which `SCustomPayload::read` keeps.
fn plugin_message_data(data: &[u8], version: JavaMinecraftVersion) -> &[u8] {
    if version < JavaMinecraftVersion::V_1_8 && data.len() >= 2 {
        &data[2..]
    } else {
        data
    }
}

/// The body to send after the channel name of a plugin message to a client: on 1.7 the data is
/// prefixed with its length as an i16.
fn plugin_message_body(data: Vec<u8>, version: JavaMinecraftVersion) -> Vec<u8> {
    if version < JavaMinecraftVersion::V_1_8 {
        let len = i16::try_from(data.len()).unwrap_or(i16::MAX);
        let mut body = Vec::with_capacity(2 + data.len());
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&data[..len as usize]);
        body
    } else {
        data
    }
}

#[derive(Clone)]
struct PendingSuggestion {
    clean_cmd: String,
    offset: usize,
    proxy_matches: Vec<(String, Option<String>)>,
}

/// Moves a client into the configuration state for a backend it is switching to.
///
/// `login_backend` stops at Login Success, so the new backend is still in the login state, waiting
/// for Login Acknowledged. A 1.20.2+ client in play answers Start Configuration with Configuration
/// Acknowledged. That is when the login is acknowledged on the backend, instead of passing the
/// client's packet through, which the backend can't handle in the login state. Play packets the
/// client sends before its acknowledgement are dropped, as they belong to the old server.
#[allow(clippy::too_many_arguments)]
async fn reenter_configuration<R, W, B>(
    client_version: JavaMinecraftVersion,
    backend_version: JavaMinecraftVersion,
    wait: Duration,
    username: &str,
    server_name: &str,
    client_decoder: &mut TCPNetworkDecoder<R>,
    client_encoder: &mut TCPNetworkEncoder<W>,
    backend_encoder: &mut TCPNetworkEncoder<B>,
    in_config: &AtomicBool,
) -> Result<(), BridgeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    B: AsyncWrite + Unpin,
{
    if client_version < JavaMinecraftVersion::V_1_20_2 {
        return Ok(());
    }

    let start = CStartConfiguration
        .serialize_for_client(ConnectionState::Play, client_version)
        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
    client_encoder
        .write_packet(start)
        .await
        .map_err(|e| BridgeError::ClientGone(e.to_string()))?;
    client_encoder
        .flush()
        .await
        .map_err(|e| BridgeError::ClientGone(e.to_string()))?;

    let acknowledged_id = protocol::serverbound_id::<SConfigurationAcknowledged>(
        ConnectionState::Play,
        client_version,
    );
    loop {
        let packet = timeout(wait, client_decoder.get_raw_packet())
            .await
            .map_err(|_| BridgeError::ClientGone("no Configuration Acknowledged".to_string()))?
            .map_err(|e| BridgeError::ClientGone(e.to_string()))?;
        if Some(packet.id) == acknowledged_id {
            in_config.store(true, Ordering::Release);
            break;
        }
        debug!(
            "Dropping play packet {} from '{}' while switching to '{}'",
            packet.id, username, server_name
        );
    }

    acknowledge_login(backend_version, backend_encoder).await
}

/// Sends Login Acknowledged to a backend that is waiting for it after Login Success.
async fn acknowledge_login<B: AsyncWrite + Unpin>(
    backend_version: JavaMinecraftVersion,
    backend_encoder: &mut TCPNetworkEncoder<B>,
) -> Result<(), BridgeError> {
    let acknowledged = SLoginAcknowledged
        .serialize_for_server(ConnectionState::Login, backend_version)
        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
    backend_encoder
        .write_packet(acknowledged)
        .await
        .map_err(|e| BridgeError::EncodeError(e.to_string()))?;
    backend_encoder
        .flush()
        .await
        .map_err(|e| BridgeError::EncodeError(e.to_string()))
}

/// The servers a player who lost `lost` is tried on, in order: the one a plugin picked in
/// `server-kick`, the configured fallback, then the limbo. Each once, only registered ones,
/// never `lost` itself (except the limbo, which is tried again if it was the one lost).
pub fn fallback_order(
    plugin: Option<&str>,
    configured: Option<&str>,
    limbo: Option<&str>,
    lost: &str,
    registered: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut order: Vec<String> = Vec::new();
    for (name, may_be_lost) in [(plugin, false), (configured, false), (limbo, true)] {
        let Some(name) = name.filter(|n| !n.is_empty()) else {
            continue;
        };
        if (name == lost && !may_be_lost) || !registered(name) || order.iter().any(|n| n == name) {
            continue;
        }
        order.push(name.to_string());
    }
    order
}

/// What a player who was moved off `lost` is told by default.
fn moved_notice(lost: &str, reason: Option<&str>, to: &str) -> String {
    match reason.map(str::trim).filter(|r| !r.is_empty()) {
        Some(reason) => format!("§cYou were moved from {lost} to {to}: §f{reason}"),
        None => format!("§cYou lost the connection to {lost}, so you were moved to {to}."),
    }
}

/// What a player whose first server couldn't be reached is told by default.
fn unreachable_notice(target: &str, to: &str) -> String {
    format!("§e{target} couldn't take you right now, so you're on {to}.")
}

/// Completions for a pre-1.13 tab-complete request: proxy command names (with their slash) and
/// arguments of proxy commands. Anything else gets none: the backend can't read the old
/// request.
fn legacy_tab_complete(
    text: &str,
    dispatcher: &CommandDispatcher,
    source: &ProxyCommandSource,
) -> Vec<String> {
    let Some(command) = text.strip_prefix('/') else {
        return Vec::new();
    };
    let words = dispatcher.suggest(command, source);
    if command.contains(' ') {
        words.into_iter().map(|s| s.suggestion).collect()
    } else {
        words
            .into_iter()
            .map(|s| format!("/{}", s.suggestion))
            .collect()
    }
}

/// A pre-1.13 tab-complete response: the number of matches, then each match.
fn legacy_tab_complete_response(id: i32, words: &[String]) -> Bytes {
    let mut payload = Vec::new();
    let _ = VarInt(words.len() as i32).encode(&mut payload);
    for word in words {
        let _ = VarInt(word.len() as i32).encode(&mut payload);
        payload.extend_from_slice(word.as_bytes());
    }
    legacy::frame(id, &payload)
}

fn decode_backend_suggestions(
    payload: &mut &[u8],
    version: &JavaMinecraftVersion,
) -> Result<
    (
        VarInt,
        VarInt,
        VarInt,
        Vec<pumpkin_protocol::java::client::play::CommandSuggestion>,
    ),
    (),
> {
    if *version >= JavaMinecraftVersion::V_1_13 {
        let id = payload.get_var_int().map_err(|_| ())?;
        let start = payload.get_var_int().map_err(|_| ())?;
        let length = payload.get_var_int().map_err(|_| ())?;
        let count = payload.get_var_int().map_err(|_| ())?.0;
        if !(0..=20000).contains(&count) {
            return Err(());
        }
        let mut matches = Vec::with_capacity((count as usize).min(1024));
        for _ in 0..count {
            let suggestion = payload.get_str().map_err(|_| ())?.to_string();
            let has_tooltip = payload.get_bool().map_err(|_| ())?;
            let tooltip = if has_tooltip {
                payload.get_component(version).ok()
            } else {
                None
            };
            matches.push(pumpkin_protocol::java::client::play::CommandSuggestion {
                suggestion,
                tooltip,
            });
        }
        Ok((id, start, length, matches))
    } else {
        Err(())
    }
}

fn inject_proxy_commands(
    payload: &[u8],
    client_version: &JavaMinecraftVersion,
    permitted_commands: &[(&str, &str)],
) -> Option<Vec<u8>> {
    if *client_version < JavaMinecraftVersion::V_1_13 || permitted_commands.is_empty() {
        return None;
    }

    if payload.last() != Some(&0) {
        return None;
    }

    let mut cur = payload;
    let node_count = cur.get_var_int().ok()?.0;
    if node_count <= 0 {
        return None;
    }

    let flags = cur.get_u8().ok()?;
    if flags != 0 {
        return None;
    }

    let children_count = cur.get_var_int().ok()?.0;
    if children_count < 0 {
        return None;
    }

    let mut original_children = Vec::with_capacity(children_count as usize);
    for _ in 0..children_count {
        let child = cur.get_var_int().ok()?;
        original_children.push(child);
    }

    if cur.is_empty() {
        return None;
    }

    let nodes1_to_end = &cur[..cur.len() - 1];

    let base_index = node_count as usize;
    let mut next_node_idx = base_index;
    let mut new_root_children = Vec::new();
    let mut extra_nodes_buf = Vec::new();

    for (cmd_name, _) in permitted_commands {
        let takes_args = matches!(*cmd_name, "server" | "send" | "help");
        if takes_args {
            let lit_node = ProtoNode {
                children: vec![VarInt((next_node_idx + 1) as i32)].into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: cmd_name,
                    is_executable: *cmd_name != "send",
                    redirect_target: None,
                    restricted: false,
                },
            };
            let arg_node = ProtoNode {
                children: Vec::new().into_boxed_slice(),
                node_type: ProtoNodeType::Argument {
                    name: "args",
                    is_executable: true,
                    redirect_target: None,
                    parser: ArgumentType::String(StringProtoArgBehavior::GreedyPhrase),
                    override_suggestion_type: Some(SuggestionProviders::AskServer),
                    restricted: false,
                },
            };

            lit_node
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;
            arg_node
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;

            new_root_children.push(VarInt(next_node_idx as i32));
            next_node_idx += 2;
        } else {
            let lit_node = ProtoNode {
                children: Vec::new().into_boxed_slice(),
                node_type: ProtoNodeType::Literal {
                    name: cmd_name,
                    is_executable: true,
                    redirect_target: None,
                    restricted: false,
                },
            };

            lit_node
                .write_to(&mut extra_nodes_buf, client_version)
                .ok()?;

            new_root_children.push(VarInt(next_node_idx as i32));
            next_node_idx += 1;
        }
    }

    let total_nodes = next_node_idx as i32;
    let total_root_children = original_children.len() + new_root_children.len();

    let mut new_payload = Vec::with_capacity(payload.len() + extra_nodes_buf.len() + 64);
    let _ = VarInt(total_nodes).encode(&mut new_payload);
    new_payload.push(0x00);
    let _ = VarInt(total_root_children as i32).encode(&mut new_payload);
    for child in original_children {
        let _ = child.encode(&mut new_payload);
    }
    for child in new_root_children {
        let _ = child.encode(&mut new_payload);
    }
    new_payload.extend_from_slice(nodes1_to_end);
    new_payload.extend_from_slice(&extra_nodes_buf);
    new_payload.push(0x00);

    Some(new_payload)
}

impl BackendBridge {
    /// Tunnels packets back and forth between client and backend
    #[allow(clippy::too_many_arguments)]
    async fn bridge_tunnel<R1, W1, R2, W2>(
        username: &str,
        client_decoder: &mut TCPNetworkDecoder<R1>,
        client_encoder: &mut TCPNetworkEncoder<W1>,
        backend_decoder: &mut TCPNetworkDecoder<R2>,
        backend_encoder: &mut TCPNetworkEncoder<W2>,
        max_packets_per_sec: u32,
        client_version: JavaMinecraftVersion,
        legacy: Option<&legacy::Session>,
        action_rx: &mut tokio::sync::mpsc::UnboundedReceiver<PlayerAction>,
        action_tx: &tokio::sync::mpsc::UnboundedSender<PlayerAction>,
        command_dispatcher: Arc<CommandDispatcher>,
        proxy_config: Arc<Config>,
        session_manager: Arc<SessionManager>,
        plugin_manager: Arc<PluginManager>,
        player_uuid: uuid::Uuid,
        current_server_name: String,
        in_config: &AtomicBool,
    ) -> Result<TunnelExit, BridgeError>
    where
        R1: AsyncRead + Unpin,
        W1: AsyncWrite + Unpin,
        R2: AsyncRead + Unpin,
        W2: AsyncWrite + Unpin,
    {
        let mut client_rate_limiter = PacketRateLimiter::new(max_packets_per_sec);
        // Ids in the client's version; `None` when the client has no such packet. The backend
        // speaks the client's version too, so clientbound ids are the same on both sides.
        let play = ConnectionState::Play;
        let chat_command_id = protocol::serverbound_id::<SChatCommand>(play, client_version);
        let chat_command_signed_id =
            protocol::serverbound_id::<SChatCommandSigned>(play, client_version);
        let chat_message_id = protocol::serverbound_id::<SChatMessage>(play, client_version);
        let custom_payload_id = protocol::serverbound_id::<SCustomPayload>(play, client_version);
        // Before 1.13 tab completion has no request id and a plain list of words as the
        // response. Vine answers it itself (`legacy_tab_complete`).
        let (command_suggestion_id, legacy_tab_complete_id) =
            if client_version >= JavaMinecraftVersion::V_1_13 {
                (
                    protocol::serverbound_id::<SCommandSuggestion>(play, client_version),
                    None,
                )
            } else {
                (
                    None,
                    protocol::serverbound_id::<SCommandSuggestion>(play, client_version),
                )
            };
        let command_suggestions_clientbound_id =
            protocol::clientbound_id::<CCommandSuggestions>(play, client_version);
        let commands_packet_id = protocol::clientbound_id::<CCommands>(play, client_version);
        let play_disconnect_id = protocol::clientbound_id::<CPlayDisconnect>(play, client_version);
        let config = ConnectionState::Config;
        let finish_config_id = protocol::clientbound_id::<CFinishConfig>(config, client_version);
        let config_disconnect_id =
            protocol::clientbound_id::<CConfigDisconnect>(config, client_version);

        let pending_suggestions: Arc<
            tokio::sync::Mutex<std::collections::HashMap<i32, PendingSuggestion>>,
        > = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let (client_tx, mut client_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

        let client_writer = async {
            while let Some(packet_bytes) = client_rx.recv().await {
                if let Err(e) = client_encoder.write_packet(packet_bytes).await {
                    debug!("Client write failed for '{}': {:?}", username, e);
                    return TunnelExit::ClientDisconnected;
                }
                if let Err(e) = client_encoder.flush().await {
                    debug!("Client flush failed for '{}': {:?}", username, e);
                    return TunnelExit::ClientDisconnected;
                }
            }
            TunnelExit::ClientDisconnected
        };

        // Packets for the backend, from the client (translated) and from Vine's own answers to
        // the backend. Written in order, flushed once the queue is empty.
        let (backend_tx, mut backend_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        let backend_writer = async {
            while let Some(packet) = backend_rx.recv().await {
                let mut next = Some(packet);
                while let Some(packet) = next {
                    if let Err(e) = backend_encoder.write_packet(packet).await {
                        debug!("Backend write failed for '{}': {:?}", username, e);
                        return TunnelExit::BackendDisconnected { reason: None };
                    }
                    next = backend_rx.try_recv().ok();
                }
                if let Err(e) = backend_encoder.flush().await {
                    debug!("Backend flush failed for '{}': {:?}", username, e);
                    return TunnelExit::BackendDisconnected { reason: None };
                }
            }
            TunnelExit::BackendDisconnected { reason: None }
        };

        let client_to_backend = async {
            loop {
                match client_decoder.get_raw_packet().await {
                    Ok(raw_packet) => {
                        if !client_rate_limiter.record_packet() {
                            warn!(
                                "Player '{}' exceeded packet rate limit (flood protection kicked in)",
                                username
                            );
                            return TunnelExit::ClientDisconnected;
                        }

                        // Clients send `chat_command_signed` instead of `chat_command`
                        // when the command has signed arguments; Geyser always does.
                        // Before 1.19 there is no chat_command packet: a command is a chat
                        // message starting with '/'.
                        let command = if Some(raw_packet.id) == chat_command_id {
                            let mut payload = &raw_packet.payload[..];
                            SChatCommand::read(&mut payload, &client_version)
                                .ok()
                                .map(|packet| packet.command)
                        } else if Some(raw_packet.id) == chat_command_signed_id {
                            let mut payload = &raw_packet.payload[..];
                            SChatCommandSigned::read(&mut payload, &client_version)
                                .ok()
                                .map(|packet| packet.command)
                        } else if client_version < JavaMinecraftVersion::V_1_19
                            && Some(raw_packet.id) == chat_message_id
                        {
                            let mut payload = &raw_packet.payload[..];
                            SChatMessage::read(&mut payload, &client_version)
                                .ok()
                                .and_then(|packet| packet.message.strip_prefix('/'))
                        } else {
                            None
                        };
                        let is_command = command.is_some();
                        if let Some(cmd_text) = command {
                            let mut cmd_event = PlayerCommandEvent {
                                uuid: player_uuid.to_string(),
                                username: username.to_string(),
                                command: cmd_text.to_string(),
                                cancelled: false,
                            };
                            plugin_manager.fire_player_command(&mut cmd_event).await;
                            if cmd_event.cancelled {
                                continue;
                            }

                            let first_word = cmd_event
                                .command
                                .split_whitespace()
                                .next()
                                .unwrap_or(&cmd_event.command);
                            if command_dispatcher.has_command(first_word) {
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                command_dispatcher.handle_command(&source, &cmd_event.command);
                                continue;
                            }
                        }
                        if Some(raw_packet.id) == chat_message_id && !is_command {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(chat_msg) = SChatMessage::read(&mut payload, &client_version)
                            {
                                let mut chat_event = PlayerChatEvent {
                                    uuid: player_uuid.to_string(),
                                    username: username.to_string(),
                                    message: chat_msg.message.to_string(),
                                    cancelled: false,
                                };
                                plugin_manager.fire_player_chat(&mut chat_event).await;
                                if chat_event.cancelled {
                                    continue;
                                }
                            }
                        }

                        if Some(raw_packet.id) == custom_payload_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(custom_payload) =
                                SCustomPayload::read(&mut payload, &client_version)
                            {
                                let mut msg_event = PluginMessageEvent {
                                    channel: custom_payload.channel.to_string(),
                                    data: plugin_message_data(custom_payload.data, client_version)
                                        .to_vec(),
                                    player_uuid: Some(player_uuid.to_string()),
                                    server_name: Some(current_server_name.clone()),
                                    cancelled: false,
                                };
                                plugin_manager.fire_plugin_message(&mut msg_event).await;
                                if msg_event.cancelled {
                                    continue;
                                }
                            }
                        }

                        if Some(raw_packet.id) == legacy_tab_complete_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(text) = payload.get_str()
                                && let Some(id) = command_suggestions_clientbound_id
                            {
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                let words =
                                    legacy_tab_complete(&text, &command_dispatcher, &source);
                                let _ = client_tx.send(legacy_tab_complete_response(id, &words));
                            }
                            continue;
                        }

                        if Some(raw_packet.id) == command_suggestion_id {
                            let mut payload = &raw_packet.payload[..];
                            if let Ok(suggestion_req) =
                                SCommandSuggestion::read(&mut payload, &client_version)
                            {
                                let raw_cmd = &suggestion_req.command;
                                let clean_cmd = raw_cmd.strip_prefix('/').unwrap_or(raw_cmd);
                                let first_word =
                                    clean_cmd.split_whitespace().next().unwrap_or(clean_cmd);
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };

                                // 1. Arguments to a proxy command (contains a space, e.g. "/server ", "/send ")
                                if clean_cmd.contains(' ')
                                    && command_dispatcher.has_command(first_word)
                                {
                                    let suggestions =
                                        command_dispatcher.suggest_with_range(clean_cmd, &source);
                                    let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                    let matches: Box<[pumpkin_protocol::java::client::play::CommandSuggestion]> = suggestions
                                        .suggestions
                                        .into_iter()
                                        .map(|s| pumpkin_protocol::java::client::play::CommandSuggestion {
                                            suggestion: s.text.cached_text().clone(),
                                            tooltip: s.tooltip,
                                        })
                                        .collect();
                                    let resp = CCommandSuggestions::new(
                                        suggestion_req.id,
                                        VarInt((suggestions.range.start + offset) as i32),
                                        VarInt(suggestions.range.len() as i32),
                                        matches,
                                    );
                                    if let Ok(bytes) = resp
                                        .serialize_for_client(ConnectionState::Play, client_version)
                                    {
                                        let _ = client_tx.send(bytes);
                                    }
                                    continue;
                                }

                                // 2. Root command name completion (no space, e.g. "/", "/s", "/ser", "/server")
                                if !clean_cmd.contains(' ') {
                                    let clean_lower = clean_cmd.to_ascii_lowercase();
                                    let permitted =
                                        command_dispatcher.get_all_permitted_commands(&source);
                                    let proxy_matches: Vec<(String, Option<String>)> = permitted
                                        .into_iter()
                                        .filter(|(cmd_name, _)| cmd_name.starts_with(&clean_lower))
                                        .map(|(cmd_name, description)| {
                                            (cmd_name.to_string(), Some(description.to_string()))
                                        })
                                        .collect();

                                    if !proxy_matches.is_empty() {
                                        let offset = if raw_cmd.starts_with('/') { 1 } else { 0 };
                                        let req_id = suggestion_req.id.0;

                                        pending_suggestions.lock().await.insert(
                                            req_id,
                                            PendingSuggestion {
                                                clean_cmd: clean_cmd.to_string(),
                                                offset,
                                                proxy_matches,
                                            },
                                        );

                                        let pending_ref = pending_suggestions.clone();
                                        let client_tx_clone = client_tx.clone();
                                        let cv = client_version;
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(200)).await;
                                            if let Some(pending) =
                                                pending_ref.lock().await.remove(&req_id)
                                            {
                                                let suggestions: Vec<pumpkin_protocol::java::client::play::CommandSuggestion> = pending
                                                    .proxy_matches
                                                    .into_iter()
                                                    .map(|(cmd, tip)| pumpkin_protocol::java::client::play::CommandSuggestion {
                                                        suggestion: cmd,
                                                        tooltip: tip.map(TextComponent::text),
                                                    })
                                                    .collect();
                                                let resp = CCommandSuggestions::new(
                                                    VarInt(req_id),
                                                    VarInt(pending.offset as i32),
                                                    VarInt(pending.clean_cmd.len() as i32),
                                                    suggestions.into_boxed_slice(),
                                                );
                                                if let Ok(bytes) = resp
                                                    .serialize_for_client(ConnectionState::Play, cv)
                                                {
                                                    let _ = client_tx_clone.send(bytes);
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }

                        let frames = match legacy {
                            Some(session) => {
                                session.serverbound(raw_packet.id, &raw_packet.payload)
                            }
                            None => vec![legacy::frame(raw_packet.id, &raw_packet.payload)],
                        };
                        for frame in frames {
                            if backend_tx.send(frame).is_err() {
                                return TunnelExit::BackendDisconnected { reason: None };
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Client '{}' stream ended: {:?}", username, e);
                        return TunnelExit::ClientDisconnected;
                    }
                }
            }
        };

        let backend_to_client = async {
            loop {
                match backend_decoder.get_raw_packet().await {
                    Ok(raw_packet) => {
                        // Translated for an old client: the backend speaks the current version.
                        let (packets, play) = match legacy {
                            Some(session) => {
                                let translated =
                                    session.clientbound(raw_packet.id, &raw_packet.payload);
                                for reply in translated.to_backend {
                                    if backend_tx.send(reply).is_err() {
                                        return TunnelExit::BackendDisconnected { reason: None };
                                    }
                                }
                                let packets: Vec<(i32, Bytes)> = translated
                                    .to_client
                                    .into_iter()
                                    .map(|(id, payload)| (id, Bytes::from(payload)))
                                    .collect();
                                (packets, translated.play)
                            }
                            None => (vec![(raw_packet.id, raw_packet.payload)], true),
                        };
                        for (packet_id, packet_payload) in packets {
                            // Configuration packets reuse play ids; only play is inspected,
                            // apart from the end of configuration and a disconnect in it.
                            if !play || in_config.load(Ordering::Acquire) {
                                if Some(packet_id) == config_disconnect_id {
                                    let mut cur = &packet_payload[..];
                                    let reason = cur
                                        .get_component(&client_version)
                                        .map(|c| c.to_pretty_console())
                                        .ok();
                                    return TunnelExit::BackendDisconnected { reason };
                                }
                                if Some(packet_id) == finish_config_id {
                                    in_config.store(false, Ordering::Release);
                                }
                                if client_tx
                                    .send(legacy::frame(packet_id, &packet_payload))
                                    .is_err()
                                {
                                    return TunnelExit::ClientDisconnected;
                                }
                                continue;
                            }
                            if Some(packet_id) == play_disconnect_id {
                                let mut cur = &packet_payload[..];
                                let reason = cur
                                    .get_component(&client_version)
                                    .map(|c| c.to_pretty_console())
                                    .ok()
                                    .or_else(|| {
                                        let s =
                                            String::from_utf8_lossy(&packet_payload).to_string();
                                        if s.is_empty() { None } else { Some(s) }
                                    });
                                return TunnelExit::BackendDisconnected { reason };
                            }

                            if Some(packet_id) == command_suggestions_clientbound_id {
                                let mut cur = &packet_payload[..];
                                if let Ok((id, start, length, mut backend_matches)) =
                                    decode_backend_suggestions(&mut cur, &client_version)
                                    && let Some(pending) =
                                        pending_suggestions.lock().await.remove(&id.0)
                                {
                                    for (cmd_name, tooltip) in pending.proxy_matches {
                                        if !backend_matches
                                            .iter()
                                            .any(|bm| bm.suggestion.eq_ignore_ascii_case(&cmd_name))
                                        {
                                            backend_matches.push(pumpkin_protocol::java::client::play::CommandSuggestion {
                                                suggestion: cmd_name,
                                                tooltip: tooltip.map(TextComponent::text),
                                            });
                                        }
                                    }
                                    backend_matches.sort_by(|a, b| a.suggestion.cmp(&b.suggestion));

                                    let merged = CCommandSuggestions::new(
                                        id,
                                        start,
                                        length,
                                        backend_matches.into_boxed_slice(),
                                    );
                                    if let Ok(bytes) = merged
                                        .serialize_for_client(ConnectionState::Play, client_version)
                                    {
                                        if client_tx.send(bytes).is_err() {
                                            return TunnelExit::ClientDisconnected;
                                        }
                                        continue;
                                    }
                                }
                            }

                            if Some(packet_id) == commands_packet_id {
                                let source = ProxyCommandSource {
                                    sender: CommandSender::Player {
                                        username: username.to_string(),
                                        action_tx: action_tx.clone(),
                                    },
                                    config: proxy_config.clone(),
                                    session_manager: session_manager.clone(),
                                };
                                let permitted =
                                    command_dispatcher.get_all_permitted_commands(&source);
                                let permitted_refs: Vec<(&str, &str)> = permitted
                                    .iter()
                                    .map(|(k, v)| (k.as_str(), v.as_str()))
                                    .collect();

                                if let Some(modified_payload) = inject_proxy_commands(
                                    &packet_payload,
                                    &client_version,
                                    &permitted_refs,
                                ) {
                                    let mut full_packet =
                                        Vec::with_capacity(5 + modified_payload.len());
                                    let _ = VarInt(packet_id).encode(&mut full_packet);
                                    full_packet.extend_from_slice(&modified_payload);

                                    if client_tx.send(full_packet.into()).is_err() {
                                        return TunnelExit::ClientDisconnected;
                                    }
                                    continue;
                                }
                            }

                            let mut full_packet = Vec::with_capacity(5 + packet_payload.len());
                            let _ = VarInt(packet_id).encode(&mut full_packet);
                            full_packet.extend_from_slice(&packet_payload);

                            if client_tx.send(full_packet.into()).is_err() {
                                return TunnelExit::ClientDisconnected;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Backend stream ended for '{}': {:?}", username, e);
                        return TunnelExit::BackendDisconnected {
                            reason: Some(e.to_string()),
                        };
                    }
                }
            }
        };

        let action_loop = async {
            while let Some(action) = action_rx.recv().await {
                match action {
                    PlayerAction::Connect { server_name } => {
                        return TunnelExit::Connect { server_name };
                    }
                    PlayerAction::Transfer { host, port } => {
                        return TunnelExit::Transfer { host, port };
                    }
                    PlayerAction::Message(text_comp) => {
                        let chat_msg = CSystemChatMessage::new(&text_comp, false);
                        if let Ok(bytes) =
                            chat_msg.serialize_for_client(ConnectionState::Play, client_version)
                        {
                            let _ = client_tx.send(bytes);
                        }
                    }
                    PlayerAction::Disconnect(reason) => {
                        return TunnelExit::Disconnect { reason };
                    }
                    PlayerAction::ActionBar(text) => {
                        // Before 1.17 the action bar is a chat message in its own slot.
                        let bytes = CActionBar::new(&text)
                            .serialize_for_client(ConnectionState::Play, client_version)
                            .or_else(|_| {
                                CSystemChatMessage::new(&text, true)
                                    .serialize_for_client(ConnectionState::Play, client_version)
                            });
                        if let Ok(bytes) = bytes {
                            let _ = client_tx.send(bytes);
                        }
                    }
                    PlayerAction::Title {
                        title,
                        subtitle,
                        fade_in,
                        stay,
                        fade_out,
                    } => {
                        let packets = [
                            CTitleAnimation::new(fade_in, stay, fade_out)
                                .serialize_for_client(ConnectionState::Play, client_version),
                            CSubtitle::new(&subtitle)
                                .serialize_for_client(ConnectionState::Play, client_version),
                            CTitleText::new(&title)
                                .serialize_for_client(ConnectionState::Play, client_version),
                        ];
                        if packets.iter().all(Result::is_ok) {
                            for bytes in packets.into_iter().flatten() {
                                let _ = client_tx.send(bytes);
                            }
                        } else {
                            // No title packets for this client: say it in chat.
                            for text in [title, subtitle] {
                                if let Ok(bytes) = CSystemChatMessage::new(&text, false)
                                    .serialize_for_client(ConnectionState::Play, client_version)
                                {
                                    let _ = client_tx.send(bytes);
                                }
                            }
                        }
                    }
                    PlayerAction::PluginMessage { channel, data } => {
                        let data = plugin_message_body(data, client_version);
                        let custom_payload =
                            pumpkin_protocol::java::client::play::CCustomPayload::new(
                                &channel, &data,
                            );
                        if let Ok(bytes) = custom_payload
                            .serialize_for_client(ConnectionState::Play, client_version)
                        {
                            let _ = client_tx.send(bytes);
                        }
                    }
                }
            }
            TunnelExit::ClientDisconnected
        };

        let exit = tokio::select! {
            exit = client_to_backend => exit,
            exit = backend_writer => exit,
            exit = backend_to_client => exit,
            exit = action_loop => exit,
            exit = client_writer => exit,
        };

        Ok(exit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pumpkin_protocol::ClientPacket;
    use pumpkin_protocol::java::client::play::CommandSuggestion;
    use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder as Decoder;
    use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder as Encoder;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

    fn packet_bytes(id: i32, payload: &[u8]) -> Bytes {
        let mut buf = Vec::new();
        let _ = VarInt(id).encode(&mut buf);
        buf.extend_from_slice(payload);
        Bytes::from(buf)
    }

    /// A length-prefixed string, as in a 1.12.2 chat or disconnect packet.
    fn string_payload(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = VarInt(s.len() as i32).encode(&mut buf);
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    /// The far ends of a tunnel: what the client and the backend send and see.
    struct Peers {
        client: Encoder<WriteHalf<DuplexStream>>,
        client_view: Decoder<ReadHalf<DuplexStream>>,
        backend: Encoder<WriteHalf<DuplexStream>>,
        backend_view: Decoder<ReadHalf<DuplexStream>>,
    }

    impl Peers {
        async fn send_from_client(&mut self, packet: Bytes) {
            self.client.write_packet(packet).await.unwrap();
            self.client.flush().await.unwrap();
        }

        async fn send_from_backend(&mut self, packet: Bytes) {
            self.backend.write_packet(packet).await.unwrap();
            self.backend.flush().await.unwrap();
        }

        async fn next_to_client(&mut self) -> pumpkin_protocol::RawPacket {
            timeout(Duration::from_secs(5), self.client_view.get_raw_packet())
                .await
                .expect("nothing reached the client")
                .unwrap()
        }
    }

    /// Runs `bridge_tunnel` for a client on `version` while `drive` plays both peers. Returns
    /// how the tunnel ended and the packets the backend received.
    async fn run_tunnel<F, Fut>(
        version: JavaMinecraftVersion,
        legacy: Option<Arc<legacy::Session>>,
        drive: F,
    ) -> (TunnelExit, Vec<pumpkin_protocol::RawPacket>)
    where
        F: FnOnce(Peers) -> Fut,
        Fut: std::future::Future<Output = Peers>,
    {
        run_tunnel_with(version, legacy, Vec::new(), false, drive).await
    }

    /// [`run_tunnel`] with actions queued for the player first, and the client starting in
    /// configuration if `in_config`.
    async fn run_tunnel_with<F, Fut>(
        version: JavaMinecraftVersion,
        legacy: Option<Arc<legacy::Session>>,
        actions: Vec<PlayerAction>,
        in_config: bool,
        drive: F,
    ) -> (TunnelExit, Vec<pumpkin_protocol::RawPacket>)
    where
        F: FnOnce(Peers) -> Fut,
        Fut: std::future::Future<Output = Peers>,
    {
        let (proxy_client, client) = tokio::io::duplex(1 << 16);
        let (proxy_backend, backend) = tokio::io::duplex(1 << 16);
        let (proxy_client_read, proxy_client_write) = tokio::io::split(proxy_client);
        let (proxy_backend_read, proxy_backend_write) = tokio::io::split(proxy_backend);
        let (client_read, client_write) = tokio::io::split(client);
        let (backend_read, backend_write) = tokio::io::split(backend);

        let mut client_decoder = Decoder::new(proxy_client_read);
        let mut client_encoder = Encoder::new(proxy_client_write);
        let mut backend_decoder = Decoder::new(proxy_backend_read);
        let mut backend_encoder = Encoder::new(proxy_backend_write);
        let peers = Peers {
            client: Encoder::new(client_write),
            client_view: Decoder::new(client_read),
            backend: Encoder::new(backend_write),
            backend_view: Decoder::new(backend_read),
        };

        let plugins_dir = tempfile::tempdir().unwrap();
        let plugin_manager = PluginManager::new(plugins_dir.path().to_path_buf()).unwrap();
        let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel();
        for action in actions {
            action_tx.send(action).unwrap();
        }
        #[cfg(not(feature = "legacy-clients"))]
        let _ = &legacy;

        let in_config = AtomicBool::new(in_config);
        let tunnel = BackendBridge::bridge_tunnel(
            "tester",
            &mut client_decoder,
            &mut client_encoder,
            &mut backend_decoder,
            &mut backend_encoder,
            1000,
            version,
            legacy.as_deref(),
            &mut action_rx,
            &action_tx,
            Arc::new(CommandDispatcher::new()),
            Arc::new(Config::default()),
            Arc::new(SessionManager::new()),
            plugin_manager,
            uuid::Uuid::nil(),
            "lobby".to_string(),
            &in_config,
        );
        let (exit, mut peers) = tokio::join!(
            async { timeout(Duration::from_secs(10), tunnel).await },
            drive(peers)
        );
        let exit = exit.expect("tunnel did not end").unwrap();

        // Close the proxy's side of the backend pipe, then collect what the backend got.
        drop(backend_encoder);
        drop(backend_decoder);
        let mut to_backend = Vec::new();
        while let Ok(Ok(packet)) =
            timeout(Duration::from_secs(5), peers.backend_view.get_raw_packet()).await
        {
            to_backend.push(packet);
        }
        (exit, to_backend)
    }

    #[tokio::test]
    async fn proxy_command_is_read_and_answered_with_client_ids() {
        // 1.20.4: chat_command is 0x04 and system chat 0x69 (current: 0x07 and 0x7c).
        let version = JavaMinecraftVersion::V_1_20_3;
        let (exit, to_backend) = run_tunnel(version, None, |mut peers| async move {
            peers
                .send_from_client(packet_bytes(0x04, &string_payload("help")))
                .await;
            assert_eq!(peers.next_to_client().await.id, 0x69);
            peers.send_from_backend(packet_bytes(0x1b, &[])).await;
            peers
        })
        .await;
        assert!(matches!(exit, TunnelExit::BackendDisconnected { .. }));
        assert!(
            to_backend.is_empty(),
            "the proxy command reached the backend"
        );
    }

    #[tokio::test]
    async fn pre_1_19_slash_chat_runs_proxy_commands() {
        // 1.12.2 has no chat_command packet; "/help" arrives as chat (0x02) and the answer goes
        // out as chat (0x0f).
        let version = JavaMinecraftVersion::V_1_12_2;
        let (exit, to_backend) = run_tunnel(version, None, |mut peers| async move {
            peers
                .send_from_client(packet_bytes(0x02, &string_payload("/help")))
                .await;
            assert_eq!(peers.next_to_client().await.id, 0x0f);
            // Plain chat and other commands still go to the backend.
            peers
                .send_from_client(packet_bytes(0x02, &string_payload("hello")))
                .await;
            peers
                .send_from_client(packet_bytes(0x02, &string_payload("/spawn")))
                .await;
            // Let the tunnel forward both before the backend hangs up.
            tokio::time::sleep(Duration::from_millis(100)).await;
            peers
                .send_from_backend(packet_bytes(0x1a, &string_payload("\"bye\"")))
                .await;
            peers
        })
        .await;
        assert!(matches!(exit, TunnelExit::BackendDisconnected { .. }));
        let forwarded: Vec<_> = to_backend
            .iter()
            .map(|p| (p.id, p.payload.to_vec()))
            .collect();
        assert_eq!(
            forwarded,
            vec![
                (0x02, string_payload("hello")),
                (0x02, string_payload("/spawn")),
            ]
        );
    }

    #[cfg(feature = "legacy-clients")]
    #[tokio::test]
    async fn old_client_is_translated_both_ways() {
        use crate::protocol::legacy_ids::{clientbound, serverbound};

        // 1.12.2 against a current backend: the backend's system chat becomes 1.12.2's chat
        // (0x0f), and the client's chat (0x02) reaches the backend with the current id.
        let version = JavaMinecraftVersion::V_1_12_2;
        let session = legacy::Session::new(version, uuid::Uuid::new_v4()).unwrap();
        session.reset(ConnectionState::Play);
        let (exit, to_backend) = run_tunnel(version, Some(session), |mut peers| async move {
            let text = TextComponent::text("hi");
            let mut chat = Vec::new();
            CSystemChatMessage::new(&text, false)
                .write_packet_data(&mut chat, &pumpkin_data::packet::CURRENT_MC_VERSION)
                .unwrap();
            peers
                .send_from_backend(packet_bytes(
                    clientbound::play::SYSTEM_CHAT.current(),
                    &chat,
                ))
                .await;
            assert_eq!(peers.next_to_client().await.id, 0x0f);

            peers
                .send_from_client(packet_bytes(0x02, &string_payload("hello")))
                .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let reason = TextComponent::text("bye");
            let mut disconnect = Vec::new();
            CPlayDisconnect::new(&reason)
                .write_packet_data(&mut disconnect, &pumpkin_data::packet::CURRENT_MC_VERSION)
                .unwrap();
            peers
                .send_from_backend(packet_bytes(
                    clientbound::play::DISCONNECT.current(),
                    &disconnect,
                ))
                .await;
            peers
        })
        .await;
        match exit {
            TunnelExit::BackendDisconnected { reason } => {
                assert_eq!(reason.as_deref(), Some("bye"));
            }
            other => panic!("unexpected exit: {other:?}"),
        }
        assert_eq!(to_backend.len(), 1);
        assert_eq!(to_backend[0].id, serverbound::play::CHAT.current());
        let mut payload = &to_backend[0].payload[..];
        assert_eq!(&*payload.get_str().unwrap(), "hello");
    }

    #[tokio::test]
    async fn pre_1_13_tab_completion_is_answered_by_vine() {
        // 1.8: tab complete is 0x14 (text, has position) and its answer 0x3a.
        let version = JavaMinecraftVersion::V_1_8;
        let (exit, to_backend) = run_tunnel(version, None, |mut peers| async move {
            let mut request = string_payload("/he");
            request.push(0);
            peers.send_from_client(packet_bytes(0x14, &request)).await;
            let answer = peers.next_to_client().await;
            assert_eq!(answer.id, 0x3a);
            let mut cur = &answer.payload[..];
            assert_eq!(cur.get_var_int().unwrap().0, 1);
            assert_eq!(&*cur.get_str().unwrap(), "/help");
            peers
                .send_from_backend(packet_bytes(0x40, &string_payload("\"bye\"")))
                .await;
            peers
        })
        .await;
        assert!(matches!(exit, TunnelExit::BackendDisconnected { .. }));
        assert!(to_backend.is_empty(), "the old request reached the backend");
    }

    #[test]
    fn plugin_messages_carry_a_short_length_on_1_7() {
        let v17 = JavaMinecraftVersion::V_1_7_6;
        let v18 = JavaMinecraftVersion::V_1_8;
        assert_eq!(plugin_message_data(&[0, 3, b'a', b'b', b'c'], v17), b"abc");
        assert_eq!(plugin_message_data(b"abc", v18), b"abc");
        assert_eq!(
            plugin_message_body(b"abc".to_vec(), v17),
            vec![0, 3, b'a', b'b', b'c']
        );
        assert_eq!(plugin_message_body(b"abc".to_vec(), v18), b"abc".to_vec());
    }

    #[tokio::test]
    async fn backend_disconnect_uses_the_client_id() {
        // On 1.12.2, 0x20 is chunk data and 0x1a is disconnect. Vine used to match the current
        // disconnect id (0x20), so the first chunk ended the connection.
        let version = JavaMinecraftVersion::V_1_12_2;
        let (exit, _) = run_tunnel(version, None, |mut peers| async move {
            peers
                .send_from_backend(packet_bytes(0x20, &[1, 2, 3]))
                .await;
            let forwarded = peers.next_to_client().await;
            assert_eq!(forwarded.id, 0x20);
            assert_eq!(&forwarded.payload[..], &[1, 2, 3]);

            let reason = string_payload(r#"{"text":"bye"}"#);
            peers.send_from_backend(packet_bytes(0x1a, &reason)).await;
            peers
        })
        .await;
        match exit {
            TunnelExit::BackendDisconnected { reason } => {
                assert_eq!(reason.as_deref(), Some("bye"));
            }
            other => panic!("unexpected exit: {other:?}"),
        }
    }

    #[tokio::test]
    async fn plugin_disconnect_ends_the_connection_instead_of_falling_back() {
        let version = JavaMinecraftVersion::V_26_3;
        let (exit, _) = run_tunnel_with(
            version,
            None,
            vec![PlayerAction::Disconnect("bye".into())],
            false,
            |peers| async move { peers },
        )
        .await;
        match exit {
            TunnelExit::Disconnect { reason } => assert_eq!(reason, "bye"),
            other => panic!("unexpected exit: {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_disconnect_in_configuration_moves_the_player() {
        // A backend that drops the player while they configure (after a switch) is a lost
        // backend like any other, not a packet to pass on.
        let version = JavaMinecraftVersion::V_26_3;
        let id = protocol::clientbound_id::<CConfigDisconnect>(ConnectionState::Config, version)
            .unwrap();
        let mut payload = Vec::new();
        CConfigDisconnect::new(r#"{"text":"closing"}"#)
            .write_packet_data(&mut payload, &version)
            .unwrap();
        let (exit, _) = run_tunnel_with(version, None, Vec::new(), true, |mut peers| async move {
            peers.send_from_backend(packet_bytes(id, &payload)).await;
            peers
        })
        .await;
        assert!(
            matches!(exit, TunnelExit::BackendDisconnected { .. }),
            "unexpected exit: {exit:?}"
        );
    }

    #[test]
    fn fallbacks_go_plugin_then_configured_then_limbo() {
        let registered = |name: &str| ["hub-1", "lobby", "limbo", "game-1"].contains(&name);
        assert_eq!(
            fallback_order(
                Some("hub-1"),
                Some("lobby"),
                Some("limbo"),
                "game-1",
                registered
            ),
            ["hub-1", "lobby", "limbo"]
        );
        // The lost server, unregistered names and repeats are skipped.
        assert_eq!(
            fallback_order(
                Some("game-1"),
                Some("gone"),
                Some("limbo"),
                "game-1",
                registered
            ),
            ["limbo"]
        );
        assert_eq!(
            fallback_order(Some("lobby"), Some("lobby"), None, "game-1", registered),
            ["lobby"]
        );
        // Losing the limbo itself tries it again.
        assert_eq!(
            fallback_order(None, None, Some("limbo"), "limbo", registered),
            ["limbo"]
        );
        assert!(fallback_order(None, None, None, "game-1", registered).is_empty());
    }

    #[test]
    fn default_notices_name_both_servers() {
        assert_eq!(
            moved_notice("game-1", Some("Server closed"), "lobby"),
            "§cYou were moved from game-1 to lobby: §fServer closed"
        );
        assert!(moved_notice("game-1", None, "limbo").contains("moved to limbo"));
        assert!(unreachable_notice("hub", "limbo").contains("hub couldn't take you"));
    }

    #[tokio::test]
    async fn switch_acknowledges_login_once_client_reenters_configuration() {
        let version = JavaMinecraftVersion::V_26_3;
        // proxy <-> client and proxy <-> new backend, as in-memory pipes
        let (proxy_client_side, client_side) = tokio::io::duplex(4096);
        let (proxy_backend_side, backend_side) = tokio::io::duplex(4096);
        let (proxy_client_read, proxy_client_write) = tokio::io::split(proxy_client_side);
        let (client_read, client_write) = tokio::io::split(client_side);
        let (_, proxy_backend_write) = tokio::io::split(proxy_backend_side);
        let (backend_read, _) = tokio::io::split(backend_side);

        let mut client_decoder = TCPNetworkDecoder::new(proxy_client_read);
        let mut client_encoder = TCPNetworkEncoder::new(proxy_client_write);
        let mut backend_encoder = TCPNetworkEncoder::new(proxy_backend_write);

        // The client is still in play: one stray play packet, then its acknowledgement.
        let mut client = TCPNetworkEncoder::new(client_write);
        client
            .write_packet(packet_bytes(0x1A, &[1, 2, 3]))
            .await
            .unwrap();
        client
            .write_packet(
                SConfigurationAcknowledged
                    .serialize_packet(&version)
                    .unwrap(),
            )
            .await
            .unwrap();
        client.flush().await.unwrap();

        let in_config = AtomicBool::new(false);
        reenter_configuration(
            version,
            version,
            Duration::from_secs(5),
            "tester",
            "game",
            &mut client_decoder,
            &mut client_encoder,
            &mut backend_encoder,
            &in_config,
        )
        .await
        .unwrap();
        assert!(in_config.load(Ordering::Acquire));

        let mut client_view = TCPNetworkDecoder::new(client_read);
        let to_client = client_view.get_raw_packet().await.unwrap();
        assert_eq!(
            Some(to_client.id),
            protocol::clientbound_id::<CStartConfiguration>(ConnectionState::Play, version)
        );

        let mut backend_view = TCPNetworkDecoder::new(backend_read);
        let to_backend = backend_view.get_raw_packet().await.unwrap();
        assert_eq!(
            Some(to_backend.id),
            protocol::serverbound_id::<SLoginAcknowledged>(ConnectionState::Login, version)
        );
        assert!(to_backend.payload.is_empty());
    }

    #[tokio::test]
    async fn switch_leaves_pre_configuration_clients_alone() {
        let version = JavaMinecraftVersion::V_1_20;
        let (proxy_client_side, _client_side) = tokio::io::duplex(4096);
        let (proxy_backend_side, _backend_side) = tokio::io::duplex(4096);
        let (proxy_client_read, proxy_client_write) = tokio::io::split(proxy_client_side);
        let (_, proxy_backend_write) = tokio::io::split(proxy_backend_side);

        reenter_configuration(
            version,
            version,
            Duration::from_millis(100),
            "tester",
            "game",
            &mut TCPNetworkDecoder::new(proxy_client_read),
            &mut TCPNetworkEncoder::new(proxy_client_write),
            &mut TCPNetworkEncoder::new(proxy_backend_write),
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
    }

    #[test]
    fn test_decode_backend_suggestions() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let pkt = CCommandSuggestions::new(
            VarInt(42),
            VarInt(1),
            VarInt(3),
            vec![
                CommandSuggestion {
                    suggestion: "say".to_string(),
                    tooltip: Some(TextComponent::text("broadcast message")),
                },
                CommandSuggestion {
                    suggestion: "spawnpoint".to_string(),
                    tooltip: None,
                },
            ]
            .into_boxed_slice(),
        );

        let bytes = pkt
            .serialize_packet(&version)
            .expect("serialization failed");
        let mut slice = &bytes[..];
        let _pkt_id = slice.get_var_int().expect("packet id read failed");

        let (id, start, length, matches) =
            decode_backend_suggestions(&mut slice, &version).expect("decode failed");

        assert_eq!(id.0, 42);
        assert_eq!(start.0, 1);
        assert_eq!(length.0, 3);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].suggestion, "say");
        assert!(matches[0].tooltip.is_some());
        assert_eq!(matches[1].suggestion, "spawnpoint");
        assert!(matches[1].tooltip.is_none());
    }

    #[test]
    fn test_merge_pending_proxy_and_backend_suggestions() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let mut backend_matches = vec![
            CommandSuggestion {
                suggestion: "server".to_string(), // duplicate name with proxy
                tooltip: None,
            },
            CommandSuggestion {
                suggestion: "status".to_string(),
                tooltip: None,
            },
        ];

        let pending_proxy_matches = vec![
            (
                "server".to_string(),
                Some("Switch or view backend server".to_string()),
            ),
            (
                "send".to_string(),
                Some("Send players to a backend".to_string()),
            ),
        ];

        // Deduplicate and merge proxy matches into backend matches
        for (cmd_name, tooltip) in pending_proxy_matches {
            if !backend_matches
                .iter()
                .any(|bm| bm.suggestion.eq_ignore_ascii_case(&cmd_name))
            {
                backend_matches.push(CommandSuggestion {
                    suggestion: cmd_name,
                    tooltip: tooltip.map(TextComponent::text),
                });
            }
        }
        backend_matches.sort_by(|a, b| a.suggestion.cmp(&b.suggestion));

        assert_eq!(backend_matches.len(), 3);
        assert_eq!(backend_matches[0].suggestion, "send");
        assert_eq!(backend_matches[1].suggestion, "server");
        assert_eq!(backend_matches[2].suggestion, "status");

        let merged = CCommandSuggestions::new(
            VarInt(10),
            VarInt(1),
            VarInt(1),
            backend_matches.into_boxed_slice(),
        );
        let serialized = merged.serialize_packet(&version);
        assert!(serialized.is_ok());
    }

    #[test]
    fn test_inject_proxy_commands() {
        let version = JavaMinecraftVersion::V_1_21_4;
        let root_node = ProtoNode {
            children: vec![VarInt(1)].into_boxed_slice(),
            node_type: ProtoNodeType::Root,
        };
        let say_node = ProtoNode {
            children: Vec::new().into_boxed_slice(),
            node_type: ProtoNodeType::Literal {
                name: "say",
                is_executable: true,
                redirect_target: None,
                restricted: false,
            },
        };
        let pkt = CCommands::new(vec![root_node, say_node].into_boxed_slice(), VarInt(0));
        let bytes = pkt.serialize_packet(&version).expect("serialize commands");
        let mut slice = &bytes[..];
        let _pkt_id = slice.get_var_int().expect("read pkt id");

        let permitted = [("server", "desc"), ("list", "desc")];
        let injected = inject_proxy_commands(slice, &version, &permitted)
            .expect("inject_proxy_commands failed");

        let mut cur = &injected[..];
        let total_nodes = cur.get_var_int().unwrap();
        // Original: 2 (root, say). Added: server (literal + args: 2), list (literal: 1). Total: 5.
        assert_eq!(total_nodes.0, 5);

        let root_flags = cur.get_u8().unwrap();
        assert_eq!(root_flags, 0); // Root node flag

        let root_children_count = cur.get_var_int().unwrap();
        // Original 1 (say) + 2 new root commands (server, list) = 3
        assert_eq!(root_children_count.0, 3);

        let c1 = cur.get_var_int().unwrap();
        assert_eq!(c1.0, 1); // say
        let c2 = cur.get_var_int().unwrap();
        assert_eq!(c2.0, 2); // server
        let c3 = cur.get_var_int().unwrap();
        assert_eq!(c3.0, 4); // list (index 2 is server literal, 3 is server args, 4 is list literal)

        // The packet must end with VarInt(0) for root_node_index
        assert_eq!(injected.last(), Some(&0));
    }
}
