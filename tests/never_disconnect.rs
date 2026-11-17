//! A backend that kicks a player doesn't disconnect them: Vine moves them to its limbo and
//! tells them why. Runs a real `BackendBridge` against a fake backend over TCP, with a 26.3
//! client driven by hand.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use pumpkin_data::packet::CURRENT_MC_VERSION;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::config::{CFinishConfig, CKnownPacks};
use pumpkin_protocol::java::client::login::CLoginSuccess;
use pumpkin_protocol::java::client::play::{
    CLogin, CPlayDisconnect, CStartConfiguration, CSystemChatMessage,
};
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::java::server::config::{SAcknowledgeFinishConfig, SKnownPacks};
use pumpkin_protocol::java::server::login::{SLoginAcknowledged, SLoginStart};
use pumpkin_protocol::java::server::play::SConfigurationAcknowledged;
use pumpkin_protocol::{
    ClientPacket, ConnectionState, MultiVersionJavaPacket, RawPacket, ServerPacket,
};
use pumpkin_util::text::TextComponent;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::time::timeout;

use vine::auth::AuthenticatedPlayer;
use vine::backend::BackendBridge;
use vine::command::CommandDispatcher;
use vine::config::{BackendConfig, Config, ForwardingMode};
use vine::protocol::VersionedPacket;
use vine::session::SessionManager;

fn id<P: MultiVersionJavaPacket>() -> i32 {
    P::to_id(CURRENT_MC_VERSION)
}

async fn send<W: AsyncWrite + Unpin, P: ClientPacket + MultiVersionJavaPacket>(
    encoder: &mut TCPNetworkEncoder<W>,
    state: ConnectionState,
    packet: &P,
    to_server: bool,
) {
    let bytes = if to_server {
        packet.serialize_for_server(state, CURRENT_MC_VERSION)
    } else {
        packet.serialize_for_client(state, CURRENT_MC_VERSION)
    }
    .unwrap();
    encoder.write_packet(bytes).await.unwrap();
    encoder.flush().await.unwrap();
}

async fn next<R: tokio::io::AsyncRead + Unpin>(decoder: &mut TCPNetworkDecoder<R>) -> RawPacket {
    timeout(Duration::from_secs(20), decoder.get_raw_packet())
        .await
        .expect("nothing arrived")
        .expect("connection closed")
}

/// A backend that logs the player in, configures and spawns them, then kicks them.
async fn kicking_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, write) = stream.into_split();
        let mut decoder = TCPNetworkDecoder::new(read);
        let mut encoder = TCPNetworkEncoder::new(write);
        next(&mut decoder).await; // handshake
        let start = next(&mut decoder).await;
        let player = SLoginStart::read(&mut &start.payload[..], &CURRENT_MC_VERSION).unwrap();
        send(
            &mut encoder,
            ConnectionState::Login,
            &CLoginSuccess::new(&player.uuid, &player.name, &[], false, uuid::Uuid::nil()),
            false,
        )
        .await;
        while next(&mut decoder).await.id != id::<SLoginAcknowledged>() {}
        send(&mut encoder, ConnectionState::Config, &CFinishConfig, false).await;
        while next(&mut decoder).await.id != id::<SAcknowledgeFinishConfig>() {}
        let reason = TextComponent::text("Kicked for testing");
        send(
            &mut encoder,
            ConnectionState::Play,
            &CPlayDisconnect::new(&reason),
            false,
        )
        .await;
        // Hold the connection until Vine drops it.
        let _ = decoder.get_raw_packet().await;
    });
    address
}

#[tokio::test]
async fn a_kicked_player_lands_in_limbo_with_the_reason() {
    let mut config = Config::default();
    config.routing.fallback_server = None;
    let game = BackendConfig {
        address: kicking_backend().await,
        forwarding: ForwardingMode::None,
        secret: None,
        icon_path: None,
        motd_line1: None,
        motd_line2: None,
    };
    config.servers.insert("game".into(), game.clone());
    vine::limbo::start(&config).await.unwrap();
    let config = Arc::new(config);

    let plugins = tempfile::tempdir().unwrap();
    let plugin_manager = vine::plugin::PluginManager::new(plugins.path().to_path_buf()).unwrap();
    let sessions = Arc::new(SessionManager::new());
    let bridge = BackendBridge::new(
        "game".into(),
        game,
        "127.0.0.1".parse().unwrap(),
        CURRENT_MC_VERSION,
        "localhost".into(),
        AuthenticatedPlayer::offline("kicked"),
        1000,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(config.network.clone()),
        6,
        sessions.clone(),
        Arc::new(CommandDispatcher::new()),
        config.clone(),
        plugin_manager,
    );

    let (proxy_side, client_side) = tokio::io::duplex(1 << 20);
    let (proxy_read, proxy_write) = tokio::io::split(proxy_side);
    let running = tokio::spawn(bridge.run(
        TCPNetworkDecoder::new(proxy_read),
        TCPNetworkEncoder::new(proxy_write),
    ));
    let (read, write) = tokio::io::split(client_side);
    let mut client = TCPNetworkDecoder::new(read);
    let mut to_proxy = TCPNetworkEncoder::new(write);

    // On the game server.
    assert_eq!(next(&mut client).await.id, id::<CLoginSuccess>());
    send(&mut to_proxy, ConnectionState::Login, &SLoginAcknowledged, true).await;
    assert_eq!(next(&mut client).await.id, id::<CFinishConfig>());
    send(
        &mut to_proxy,
        ConnectionState::Config,
        &SAcknowledgeFinishConfig,
        true,
    )
    .await;

    // Kicked: instead of the disconnect, Vine starts a new configuration for the limbo.
    let packet = next(&mut client).await;
    assert_ne!(packet.id, id::<CPlayDisconnect>(), "the client was disconnected");
    assert_eq!(packet.id, id::<CStartConfiguration>());
    send(
        &mut to_proxy,
        ConnectionState::Play,
        &SConfigurationAcknowledged,
        true,
    )
    .await;
    loop {
        let packet = next(&mut client).await;
        if packet.id == id::<CKnownPacks>() {
            send(
                &mut to_proxy,
                ConnectionState::Config,
                &SKnownPacks {
                    known_packs: Vec::new(),
                },
                true,
            )
            .await;
        } else if packet.id == id::<CFinishConfig>() {
            send(
                &mut to_proxy,
                ConnectionState::Config,
                &SAcknowledgeFinishConfig,
                true,
            )
            .await;
            break;
        }
    }

    // In the limbo, told why.
    let mut joined = false;
    let mut told = None;
    while told.is_none() {
        let packet = next(&mut client).await;
        if packet.id == id::<CLogin>() {
            joined = true;
        } else if packet.id == id::<CSystemChatMessage>() {
            told = Some(String::from_utf8_lossy(&packet.payload).to_string());
        }
    }
    assert!(joined, "no join from the limbo");
    let told = told.unwrap();
    assert!(told.contains("game"), "notice: {told}");
    assert!(told.contains("Kicked for testing"), "notice: {told}");
    assert_eq!(
        sessions.get_session("kicked").map(|s| s.current_server),
        Some("limbo".to_string())
    );

    drop(to_proxy);
    drop(client);
    let _ = timeout(Duration::from_secs(10), running).await;
}
