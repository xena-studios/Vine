//! Vine's built-in limbo: a tiny server the proxy answers itself, where players wait when no
//! backend can take them (every server is down, a plugin holds them back, a backend kicked
//! them and nothing else is up).
//!
//! It runs on a loopback TCP listener and is registered as an ordinary backend (forwarding
//! `none`) under `[limbo] name`, so everything Vine does with backends works for it unchanged:
//! logging in, switching away, proxy commands, and translating for old clients. It speaks the
//! current protocol version only, like the backends Vine translates for.
//!
//! What a player gets: the login, the configuration phase with the vanilla registries
//! (`pumpkin_data`'s static copy, as Pumpkin sends them), then a void world in spectator mode
//! (so the client's level-loading screen finishes without any chunks), keep-alives, an empty
//! command tree (Vine adds its own commands to it), and `[limbo] message` on arrival. Anything
//! the client sends is read and dropped. Each player costs one small task and two loopback
//! sockets; there is no world.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use pumpkin_data::dimension::Dimension;
use pumpkin_data::packet::CURRENT_MC_VERSION;
use pumpkin_data::registry::Registry;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::config::{
    CFeatureFlags, CFinishConfig, CKnownPacks, CRegistryData, CUpdateTags,
};
use pumpkin_protocol::java::client::login::CLoginSuccess;
use pumpkin_protocol::java::client::play::{
    CCommands, CGameEvent, CKeepAlive, CLogin, CPlayerPosition, CPlayerSpawnPosition,
    CSystemChatMessage, GameEvent, PlayerSpawnData, ProtoNode, ProtoNodeType,
};
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::java::server::config::{SAcknowledgeFinishConfig, SKnownPacks};
use pumpkin_protocol::java::server::handshake::SHandShake;
use pumpkin_protocol::java::server::login::{SLoginAcknowledged, SLoginStart};
use pumpkin_protocol::{ClientPacket, ConnectionState, KnownPack, MultiVersionJavaPacket};
use pumpkin_protocol::{RawPacket, ServerPacket};
use pumpkin_util::math::position::BlockPos;
use pumpkin_util::math::vector3::Vector3;
use pumpkin_util::text::TextComponent;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use crate::config::{BackendConfig, Config, ForwardingMode};
use crate::protocol::VersionedPacket;

/// `[limbo]` in `vine.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimboConfig {
    /// Run the limbo. On by default.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The server name players and plugins use for it.
    #[serde(default = "default_name")]
    pub name: String,
    /// Shown in chat when a player arrives (legacy `§` text); empty for nothing.
    #[serde(default)]
    pub message: String,
}

fn default_true() -> bool {
    true
}

fn default_name() -> String {
    "limbo".to_string()
}

impl Default for LimboConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: default_name(),
            message: String::new(),
        }
    }
}

/// How often a limbo player gets a keep-alive. The client gives up after 30 s without one.
const KEEP_ALIVE_EVERY: Duration = Duration::from_secs(10);
/// How long each step of the login and configuration may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// Where players float. Above the build limit, out of the way of anything.
const SPAWN: Vector3<f64> = Vector3::new(0.5, 400.0, 0.5);
/// Spectator: the client needs no chunks to leave its loading screen.
const SPECTATOR: u8 = 3;

/// Starts the limbo if `[limbo]` enables it and registers it as a backend. Returns its address.
pub async fn start(config: &Config) -> std::io::Result<Option<SocketAddr>> {
    if !config.limbo.enabled {
        return Ok(None);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    config.servers.set_limbo(
        config.limbo.name.clone(),
        BackendConfig {
            address: address.to_string(),
            forwarding: ForwardingMode::None,
            secret: None,
            icon_path: None,
            motd_line1: None,
            motd_line2: None,
        },
    );
    let message = config.limbo.message.clone();
    info!(
        "Limbo '{}' is answering on {} (built in)",
        config.limbo.name, address
    );
    tokio::spawn(serve(listener, message));
    Ok(Some(address))
}

async fn serve(listener: TcpListener, message: String) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let message = message.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(stream, &message).await {
                        debug!("Limbo connection from {} ended: {}", peer, err);
                    }
                });
            }
            Err(err) => {
                warn!("Limbo listener accept failed: {}", err);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle(stream: TcpStream, message: &str) -> Result<(), String> {
    let _ = stream.set_nodelay(true);
    let (read, write) = stream.into_split();
    run(
        TCPNetworkDecoder::new(read),
        TCPNetworkEncoder::new(write),
        message,
    )
    .await
}

/// One player, from the handshake until the proxy closes the connection.
pub async fn run<R, W>(
    mut decoder: TCPNetworkDecoder<R>,
    mut encoder: TCPNetworkEncoder<W>,
    message: &str,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let version = CURRENT_MC_VERSION;

    // Handshake
    let handshake = next(&mut decoder).await?;
    let hello = SHandShake::read(&mut &handshake.payload[..], &version)
        .map_err(|e| format!("bad handshake: {e}"))?;
    if hello.next_state != ConnectionState::Login {
        return Err("only logins are answered".into());
    }

    // Login
    let start = next(&mut decoder).await?;
    let player = SLoginStart::read(&mut &start.payload[..], &version)
        .map_err(|e| format!("bad login start: {e}"))?;
    send(
        &mut encoder,
        ConnectionState::Login,
        &CLoginSuccess::new(&player.uuid, &player.name, &[], false, uuid::Uuid::nil()),
    )
    .await?;
    wait_for(&mut decoder, SLoginAcknowledged::to_id(version)).await?;

    // Configuration
    let version_name = version.to_string();
    send(
        &mut encoder,
        ConnectionState::Config,
        &CFeatureFlags::new(&["minecraft:vanilla"]),
    )
    .await?;
    let packs = [KnownPack {
        namespace: "minecraft",
        id: "core",
        version: &version_name,
    }];
    send(
        &mut encoder,
        ConnectionState::Config,
        &CKnownPacks::new(&packs),
    )
    .await?;
    wait_for(&mut decoder, SKnownPacks::to_id(version)).await?;
    for registry in Registry::get_synced(version) {
        send(
            &mut encoder,
            ConnectionState::Config,
            &CRegistryData::new(&registry.registry_id, &registry.registry_entries),
        )
        .await?;
    }
    let tags: Vec<_> = pumpkin_data::tag::RegistryKey::NETWORK_KEYS
        .iter()
        .copied()
        .filter(|&key| {
            pumpkin_data::tag::get_registry_key_tags(version, key).is_some_and(|m| !m.is_empty())
        })
        .collect();
    send(
        &mut encoder,
        ConnectionState::Config,
        &CUpdateTags::new(&tags),
    )
    .await?;
    send(&mut encoder, ConnectionState::Config, &CFinishConfig).await?;
    wait_for(&mut decoder, SAcknowledgeFinishConfig::to_id(version)).await?;

    // Play: a void world, in spectator mode.
    let dimensions = vec!["minecraft:overworld".to_string()];
    let play = ConnectionState::Play;
    send(
        &mut encoder,
        play,
        &CLogin {
            entity_id: 1,
            is_hardcore: false,
            dimension_names: &dimensions,
            max_players: VarInt(1),
            view_distance: VarInt(2),
            simulated_distance: VarInt(2),
            reduced_debug_info: true,
            enabled_respawn_screen: false,
            limited_crafting: false,
            spawn_data: PlayerSpawnData::new(
                Dimension::OVERWORLD,
                0,
                SPECTATOR,
                -1,
                false,
                true,
                None,
                VarInt(0),
                VarInt(63),
            ),
            online_mode: false,
            enforce_secure_chat: false,
        },
    )
    .await?;
    send(
        &mut encoder,
        play,
        &CCommands::new(
            vec![ProtoNode {
                children: Box::new([]),
                node_type: ProtoNodeType::Root,
            }]
            .into_boxed_slice(),
            VarInt(0),
        ),
    )
    .await?;
    send(
        &mut encoder,
        play,
        &CGameEvent::new(GameEvent::StartWaitingChunks, 0.0),
    )
    .await?;
    send(
        &mut encoder,
        play,
        &CPlayerSpawnPosition::new(
            BlockPos(Vector3::new(0, 400, 0)),
            0.0,
            0.0,
            "minecraft:overworld".to_string(),
        ),
    )
    .await?;
    send(
        &mut encoder,
        play,
        &CPlayerPosition::new(
            VarInt(1),
            SPAWN,
            Vector3::new(0.0, 0.0, 0.0),
            0.0,
            0.0,
            Vec::new(),
        ),
    )
    .await?;
    if !message.is_empty() {
        let text = TextComponent::from_legacy_string(message);
        send(&mut encoder, play, &CSystemChatMessage::new(&text, false)).await?;
    }

    // Keep the player connected until the proxy moves them on.
    let mut ticker = interval(KEEP_ALIVE_EVERY);
    ticker.tick().await;
    let mut keep_alive_id: i64 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                keep_alive_id += 1;
                send(&mut encoder, play, &CKeepAlive::new(keep_alive_id)).await?;
            }
            packet = decoder.get_raw_packet() => {
                packet.map_err(|e| format!("connection closed: {e}"))?;
            }
        }
    }
}

async fn next<R: AsyncRead + Unpin>(
    decoder: &mut TCPNetworkDecoder<R>,
) -> Result<RawPacket, String> {
    timeout(STEP_TIMEOUT, decoder.get_raw_packet())
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| format!("connection closed: {e}"))
}

/// Reads packets until one with `id` arrives; everything else (client information, plugin
/// messages, keep-alives) is dropped.
async fn wait_for<R: AsyncRead + Unpin>(
    decoder: &mut TCPNetworkDecoder<R>,
    id: i32,
) -> Result<(), String> {
    loop {
        if next(decoder).await?.id == id {
            return Ok(());
        }
    }
}

async fn send<W, P>(
    encoder: &mut TCPNetworkEncoder<W>,
    state: ConnectionState,
    packet: &P,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
    P: ClientPacket + MultiVersionJavaPacket,
{
    let bytes: Bytes = packet
        .serialize_for_client(state, CURRENT_MC_VERSION)
        .map_err(|e| e.to_string())?;
    encoder
        .write_packet(bytes)
        .await
        .map_err(|e| e.to_string())?;
    encoder.flush().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pumpkin_protocol::java::client::config::CFeatureFlags;
    use pumpkin_protocol::java::server::config::SKnownPacks;
    use pumpkin_protocol::java::server::handshake::SHandShake;
    use tokio::io::{ReadHalf, WriteHalf};

    type Client = (
        TCPNetworkDecoder<ReadHalf<tokio::io::DuplexStream>>,
        TCPNetworkEncoder<WriteHalf<tokio::io::DuplexStream>>,
    );

    fn id<P: MultiVersionJavaPacket>() -> i32 {
        P::to_id(CURRENT_MC_VERSION)
    }

    async fn to_limbo<P: ClientPacket + MultiVersionJavaPacket>(
        client: &mut Client,
        state: ConnectionState,
        packet: &P,
    ) {
        let bytes = packet
            .serialize_for_server(state, CURRENT_MC_VERSION)
            .unwrap();
        client.1.write_packet(bytes).await.unwrap();
        client.1.flush().await.unwrap();
    }

    async fn from_limbo(client: &mut Client) -> RawPacket {
        timeout(Duration::from_secs(60), client.0.get_raw_packet())
            .await
            .expect("limbo went quiet")
            .expect("limbo closed")
    }

    /// Logs a client in and configures it, as Vine does for a player. Returns the client and
    /// the play packets up to the first keep-alive.
    async fn join(message: &'static str) -> (Client, Vec<RawPacket>) {
        let (limbo_side, client_side) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(limbo_side);
        tokio::spawn(async move {
            let _ = run(
                TCPNetworkDecoder::new(read),
                TCPNetworkEncoder::new(write),
                message,
            )
            .await;
        });
        let (read, write) = tokio::io::split(client_side);
        let mut client: Client = (TCPNetworkDecoder::new(read), TCPNetworkEncoder::new(write));

        to_limbo(
            &mut client,
            ConnectionState::HandShake,
            &SHandShake {
                protocol_version: VarInt(CURRENT_MC_VERSION.protocol_version()),
                server_address: "localhost".into(),
                server_port: 25565,
                next_state: ConnectionState::Login,
            },
        )
        .await;
        to_limbo(
            &mut client,
            ConnectionState::Login,
            &SLoginStart {
                name: "waiter".into(),
                uuid: uuid::Uuid::from_u128(7),
            },
        )
        .await;
        assert_eq!(from_limbo(&mut client).await.id, id::<CLoginSuccess>());
        to_limbo(&mut client, ConnectionState::Login, &SLoginAcknowledged).await;

        assert_eq!(from_limbo(&mut client).await.id, id::<CFeatureFlags>());
        assert_eq!(from_limbo(&mut client).await.id, id::<CKnownPacks>());
        to_limbo(
            &mut client,
            ConnectionState::Config,
            &SKnownPacks {
                known_packs: Vec::new(),
            },
        )
        .await;
        let mut registries = 0;
        loop {
            let packet = from_limbo(&mut client).await;
            if packet.id == id::<CFinishConfig>() {
                break;
            }
            if packet.id == id::<CRegistryData>() {
                registries += 1;
            }
        }
        assert!(registries >= 30, "only {registries} registries");
        to_limbo(&mut client, ConnectionState::Config, &SAcknowledgeFinishConfig).await;

        let mut play = Vec::new();
        loop {
            let packet = from_limbo(&mut client).await;
            let keep_alive = packet.id == id::<CKeepAlive>();
            play.push(packet);
            if keep_alive {
                return (client, play);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_player_joins_the_void_and_is_kept_alive() {
        let (mut client, play) = join("§eHold on").await;
        let ids: Vec<i32> = play.iter().map(|p| p.id).collect();
        assert_eq!(ids[0], id::<CLogin>());
        for expected in [
            id::<CCommands>(),
            id::<CGameEvent>(),
            id::<CPlayerSpawnPosition>(),
            id::<CPlayerPosition>(),
            id::<CSystemChatMessage>(),
            id::<CKeepAlive>(),
        ] {
            assert!(ids.contains(&expected), "no packet {expected} in {ids:?}");
        }
        // Spectator: the client needs no chunks.
        let login = &play[0];
        assert!(login.payload.len() > 10);

        // Anything the player sends is dropped, and the keep-alives go on.
        to_limbo(
            &mut client,
            ConnectionState::Play,
            &pumpkin_protocol::java::server::play::SKeepAlive { keep_alive_id: 1 },
        )
        .await;
        assert_eq!(from_limbo(&mut client).await.id, id::<CKeepAlive>());
    }

    #[tokio::test]
    async fn status_requests_are_not_answered() {
        let (limbo_side, client_side) = tokio::io::duplex(4096);
        let (read, write) = tokio::io::split(limbo_side);
        let (_, client_write) = tokio::io::split(client_side);
        let mut encoder = TCPNetworkEncoder::new(client_write);
        let hello = SHandShake {
            protocol_version: VarInt(CURRENT_MC_VERSION.protocol_version()),
            server_address: "localhost".into(),
            server_port: 25565,
            next_state: ConnectionState::Status,
        }
        .serialize_for_server(ConnectionState::HandShake, CURRENT_MC_VERSION)
        .unwrap();
        encoder.write_packet(hello).await.unwrap();
        encoder.flush().await.unwrap();
        let result = run(
            TCPNetworkDecoder::new(read),
            TCPNetworkEncoder::new(write),
            "",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn starts_on_loopback_and_registers_itself() {
        let config = Config::default();
        let address = start(&config).await.unwrap().expect("limbo is on by default");
        assert!(address.ip().is_loopback());
        assert_eq!(config.servers.limbo().as_deref(), Some("limbo"));
        assert_eq!(
            config.servers.get("limbo").map(|c| c.address),
            Some(address.to_string())
        );
        assert!(config.servers.is_limbo("limbo"));
        // It isn't written back into `[servers]`.
        assert!(!toml::to_string(&config.servers).unwrap().contains("limbo"));

        let mut off = Config::default();
        off.limbo.enabled = false;
        assert_eq!(start(&off).await.unwrap(), None);
        assert_eq!(off.servers.limbo(), None);
    }

    /// Old clients get the limbo through Vine's translation, like any backend.
    #[cfg(feature = "legacy-clients")]
    #[tokio::test(start_paused = true)]
    async fn old_clients_get_the_limbo_translated() {
        use pumpkin_util::version::JavaMinecraftVersion as V;
        let (_client, play) = join("").await;
        for version in [V::V_1_8, V::V_1_12_2, V::V_1_20_3, V::V_1_21_4] {
            let session = crate::legacy::Session::new(version, uuid::Uuid::from_u128(7))
                .expect("translated");
            // Clients with a configuration phase are in play once it ends.
            session.reset(if version >= V::V_1_20_2 {
                ConnectionState::Play
            } else {
                ConnectionState::Login
            });
            let mut sent = 0;
            for packet in &play {
                sent += session
                    .clientbound(packet.id, &packet.payload)
                    .to_client
                    .len();
            }
            assert!(sent > 0, "{version:?} got nothing");
        }
    }
}
