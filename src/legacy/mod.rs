//! Clients older than the current version, translated on the proxy.
//!
//! Backends only ever see the current version. Vine logs in to them as a current client and
//! translates every packet in between with `pumpkin-java-multiversion`'s translation (the
//! `legacy-clients` feature), the way ViaVersion runs on a Velocity proxy: only old clients pay
//! for it, and proxies scale out.
//!
//! What Pumpkin does itself for an old client it talks to directly, Vine does here instead:
//!
//! - Clients before 1.20.2 have no configuration state, so Vine answers the backend's
//!   configuration phase itself ([`configure_backend`]); the translated join packet carries the
//!   old registries.
//! - They don't acknowledge chunk batches, so Vine does.
//! - Clients before 1.9 don't confirm teleports, so Vine confirms the latest one when the client
//!   next moves.
//! - On a server switch, clients before 1.20.2 can't re-enter configuration: Vine sends them the
//!   new join packet followed by a respawn (into another dimension first, before 1.16), and
//!   removes the old server's tab list entries and boss bars.

use std::time::Duration;

use bytes::Bytes;
use pumpkin_data::packet::CURRENT_MC_VERSION;
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::packet_decoder::TCPNetworkDecoder;
use pumpkin_protocol::java::packet_encoder::TCPNetworkEncoder;
use pumpkin_protocol::ser::NetworkReadSliceExt;
use pumpkin_util::version::JavaMinecraftVersion;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::debug;

use crate::protocol::legacy_ids::{clientbound, serverbound};

#[cfg(feature = "legacy-clients")]
mod session;
#[cfg(feature = "legacy-clients")]
pub use session::Session;

#[cfg(not(feature = "legacy-clients"))]
mod disabled;
#[cfg(not(feature = "legacy-clients"))]
pub use disabled::Session;

/// Whether Vine translates for a client on `version`.
#[must_use]
pub fn translates(version: JavaMinecraftVersion) -> bool {
    cfg!(feature = "legacy-clients")
        && version != CURRENT_MC_VERSION
        && version != JavaMinecraftVersion::Unknown
}

/// The version Vine speaks to backends for a client on `version`.
#[must_use]
pub fn backend_version(version: JavaMinecraftVersion) -> JavaMinecraftVersion {
    if translates(version) {
        CURRENT_MC_VERSION
    } else {
        version
    }
}

/// Packets that came out of translating one backend packet.
#[derive(Debug, Default)]
pub struct Translated {
    /// `(id, payload)` in the client's version.
    pub to_client: Vec<(i32, Vec<u8>)>,
    /// Framed packets Vine answers the backend with, in the current version.
    pub to_backend: Vec<Bytes>,
    /// Whether the client packets are play packets (not configuration).
    pub play: bool,
}

/// A packet id followed by its payload, as encoders take it.
#[must_use]
pub fn frame(id: i32, payload: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(5 + payload.len());
    let _ = VarInt(id).encode(&mut buf);
    buf.extend_from_slice(payload);
    buf.into()
}

/// Takes a backend that just sent Login Success through its configuration phase on behalf of a
/// client that has none (before 1.20.2), so the backend ends up in play. Registries and tags are
/// dropped: the translated join packet carries the client's own. Returns the backend's reason
/// when it disconnects instead.
pub async fn configure_backend<R, W>(
    decoder: &mut TCPNetworkDecoder<R>,
    encoder: &mut TCPNetworkEncoder<W>,
    wait: Duration,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn send<W: AsyncWrite + Unpin>(
        encoder: &mut TCPNetworkEncoder<W>,
        id: i32,
        payload: &[u8],
    ) -> Result<(), String> {
        encoder
            .write_packet(frame(id, payload))
            .await
            .map_err(|e| e.to_string())?;
        encoder.flush().await.map_err(|e| e.to_string())
    }

    send(
        encoder,
        serverbound::login::LOGIN_ACKNOWLEDGED.current(),
        &[],
    )
    .await?;
    loop {
        let packet = timeout(wait, decoder.get_raw_packet())
            .await
            .map_err(|_| "timed out in configuration".to_string())?
            .map_err(|e| e.to_string())?;
        let id = packet.id;
        if id == clientbound::config::FINISH_CONFIGURATION.current() {
            return send(
                encoder,
                serverbound::config::FINISH_CONFIGURATION.current(),
                &[],
            )
            .await;
        } else if id == clientbound::config::SELECT_KNOWN_PACKS.current() {
            // Same layout both ways: claim the packs the backend offers, so it sends less.
            send(
                encoder,
                serverbound::config::SELECT_KNOWN_PACKS.current(),
                &packet.payload,
            )
            .await?;
        } else if id == clientbound::config::KEEP_ALIVE.current() {
            send(
                encoder,
                serverbound::config::KEEP_ALIVE.current(),
                &packet.payload,
            )
            .await?;
        } else if id == clientbound::config::PING.current() {
            send(
                encoder,
                serverbound::config::PONG.current(),
                &packet.payload,
            )
            .await?;
        } else if id == clientbound::config::RESOURCE_PACK_PUSH.current() {
            // The pack's UUID, then "successfully loaded". Old clients get no pack.
            let mut payload = packet.payload.get(..16).unwrap_or_default().to_vec();
            payload.push(0);
            send(
                encoder,
                serverbound::config::RESOURCE_PACK.current(),
                &payload,
            )
            .await?;
        } else if id == clientbound::config::DISCONNECT.current() {
            let mut cur = &packet.payload[..];
            let reason = cur
                .get_component(&CURRENT_MC_VERSION)
                .map(|c| c.get_text())
                .unwrap_or_else(|_| "Disconnected in configuration".to_string());
            return Err(reason);
        } else {
            debug!("Dropping configuration packet {id} for a client without configuration");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn current_and_unknown_clients_are_not_translated() {
        assert!(!translates(CURRENT_MC_VERSION));
        assert!(!translates(JavaMinecraftVersion::Unknown));
        assert_eq!(
            backend_version(JavaMinecraftVersion::Unknown),
            JavaMinecraftVersion::Unknown
        );
    }

    #[cfg(feature = "legacy-clients")]
    #[test]
    fn old_clients_reach_backends_as_current() {
        for version in [
            JavaMinecraftVersion::V_1_7_6,
            JavaMinecraftVersion::V_1_8,
            JavaMinecraftVersion::V_1_20_3,
            JavaMinecraftVersion::V_26_2,
        ] {
            assert!(translates(version));
            assert_eq!(backend_version(version), CURRENT_MC_VERSION);
        }
    }

    #[tokio::test]
    async fn configures_a_backend_without_the_client() {
        let (proxy, backend) = duplex(1 << 16);
        let (proxy_read, proxy_write) = tokio::io::split(proxy);
        let (backend_read, backend_write) = tokio::io::split(backend);
        let mut decoder = TCPNetworkDecoder::new(proxy_read);
        let mut encoder = TCPNetworkEncoder::new(proxy_write);
        let mut backend_out = TCPNetworkEncoder::new(backend_write);
        let mut backend_in = TCPNetworkDecoder::new(backend_read);

        let packs = [
            1u8, 9, b'm', b'i', b'n', b'e', b'c', b'r', b'a', b'f', b't', 0, 0,
        ];
        for (id, payload) in [
            (
                clientbound::config::CUSTOM_PAYLOAD.current(),
                &b"\x05brand"[..],
            ),
            (
                clientbound::config::SELECT_KNOWN_PACKS.current(),
                &packs[..],
            ),
            (clientbound::config::REGISTRY_DATA.current(), &[0u8; 4][..]),
            (
                clientbound::config::KEEP_ALIVE.current(),
                &[0, 0, 0, 0, 0, 0, 0, 7][..],
            ),
            (clientbound::config::FINISH_CONFIGURATION.current(), &[][..]),
        ] {
            backend_out.write_packet(frame(id, payload)).await.unwrap();
        }
        backend_out.flush().await.unwrap();

        configure_backend(&mut decoder, &mut encoder, Duration::from_secs(5))
            .await
            .unwrap();

        let mut answers = Vec::new();
        for _ in 0..4 {
            let packet = backend_in.get_raw_packet().await.unwrap();
            answers.push((packet.id, packet.payload.to_vec()));
        }
        assert_eq!(
            answers,
            vec![
                (serverbound::login::LOGIN_ACKNOWLEDGED.current(), vec![]),
                (
                    serverbound::config::SELECT_KNOWN_PACKS.current(),
                    packs.to_vec()
                ),
                (
                    serverbound::config::KEEP_ALIVE.current(),
                    vec![0, 0, 0, 0, 0, 0, 0, 7]
                ),
                (serverbound::config::FINISH_CONFIGURATION.current(), vec![]),
            ]
        );
    }
}
