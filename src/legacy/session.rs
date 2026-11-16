//! Per-connection translation of an old client with `pumpkin-java-multiversion`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use pumpkin_data::dimension::Dimension;
use pumpkin_data::packet::CURRENT_MC_VERSION;
use pumpkin_java_multiversion::packet::translator::{JavaConnectionState, PacketTranslator};
use pumpkin_java_multiversion::translate::{chunk, entity_data, tags};
use pumpkin_protocol::codec::var_int::VarInt;
use pumpkin_protocol::java::client::play::{CRespawn, PlayerInfoFlags, PlayerSpawnData};
use pumpkin_protocol::ser::{NetworkReadExt, NetworkReadSliceExt, NetworkWriteExt};
use pumpkin_protocol::{ClientPacket, ConnectionState};
use pumpkin_util::version::JavaMinecraftVersion;
use tracing::debug;
use uuid::Uuid;

use super::{Translated, frame, translates};
use crate::protocol::legacy_ids::{clientbound, serverbound};

/// Chunks per tick Vine asks for when it acknowledges a chunk batch for a client that can't.
const CHUNKS_PER_TICK: f32 = 25.0;

/// Translation state of one old client, kept across server switches.
pub struct Session {
    version: JavaMinecraftVersion,
    /// Key of the client's state in `pumpkin-java-multiversion`'s entity tracking.
    viewer: u128,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// State of both directions. It changes when the client's acknowledgement (login,
    /// configuration, finish configuration) passes, before the backend can answer it.
    connection: Option<ConnectionState>,
    /// The client has had a join packet.
    joined: bool,
    /// Switching servers without configuration: the client's packets belong to the old server
    /// until the new join packet reaches it.
    awaiting_join: bool,
    /// The backend's latest teleport, which the client has yet to confirm.
    teleport: Option<i32>,
    /// The player's rotation, which some older packets leave out.
    rotation: (f32, f32),
    /// Players in the client's tab list and boss bars on screen, from the current server, so a
    /// switch without configuration can remove them.
    tab_list: HashSet<Uuid>,
    boss_bars: HashSet<Uuid>,
}

fn state_name(state: ConnectionState) -> JavaConnectionState {
    match state {
        ConnectionState::HandShake => JavaConnectionState::Handshake,
        ConnectionState::Status => JavaConnectionState::Status,
        ConnectionState::Login | ConnectionState::Transfer => JavaConnectionState::Login,
        ConnectionState::Config => JavaConnectionState::Config,
        ConnectionState::Play => JavaConnectionState::Play,
    }
}

impl Session {
    /// A session for a client on `version`, or `None` when Vine doesn't translate for it.
    #[must_use]
    pub fn new(version: JavaMinecraftVersion, player: Uuid) -> Option<Arc<Self>> {
        translates(version).then(|| {
            Arc::new(Self {
                version,
                viewer: player.as_u128(),
                state: Mutex::new(State::default()),
            })
        })
    }

    fn has_configuration(&self) -> bool {
        self.version >= JavaMinecraftVersion::V_1_20_2
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts translating a new backend connection in `state`: login after Login Success on
    /// join, configuration after a switch re-entered it. Clients without configuration are
    /// always in play.
    pub fn reset(&self, state: ConnectionState) {
        let mut st = self.lock();
        st.connection = Some(if self.has_configuration() {
            state
        } else {
            ConnectionState::Play
        });
        st.teleport = None;
    }

    /// Before switching a client without configuration to a new backend: drop its packets until
    /// the new join packet reaches it.
    pub fn begin_switch(&self) {
        let mut st = self.lock();
        st.awaiting_join = true;
        st.teleport = None;
    }

    /// The backend's Login Success (id and payload) for the client.
    #[must_use]
    pub fn login_success(&self, packet: &[u8]) -> Option<Bytes> {
        let mut cur = packet;
        let id = cur.get_var_int().ok()?.0;
        let (id, payload) = PacketTranslator::translate_connection_outgoing(
            JavaConnectionState::Login,
            id,
            cur,
            self.version,
        )?;
        Some(frame(id, &payload))
    }

    /// A packet from the client, as framed packets for the backend (none, or more than one).
    #[must_use]
    pub fn serverbound(&self, id: i32, payload: &[u8]) -> Vec<Bytes> {
        let mut st = self.lock();
        let state = st.connection.unwrap_or(ConnectionState::Play);
        if state != ConnectionState::Play {
            let Some((current, payload)) = PacketTranslator::translate_connection_incoming(
                state_name(state),
                id,
                payload,
                self.version,
            ) else {
                debug!(
                    "Dropping {state:?} packet {id} from a {} client",
                    self.version
                );
                return Vec::new();
            };
            if state == ConnectionState::Login
                && current == serverbound::login::LOGIN_ACKNOWLEDGED.current()
            {
                st.connection = Some(ConnectionState::Config);
            } else if state == ConnectionState::Config
                && current == serverbound::config::FINISH_CONFIGURATION.current()
            {
                st.connection = Some(ConnectionState::Play);
            }
            return vec![frame(current, &payload)];
        }

        if st.awaiting_join {
            return Vec::new();
        }
        let rotation = st.rotation;
        let Some((current, payload)) =
            PacketTranslator::translate_incoming_packet(id, payload, self.version, || rotation)
        else {
            debug!("Dropping play packet {id} from a {} client", self.version);
            return Vec::new();
        };
        if current == serverbound::play::CONFIGURATION_ACKNOWLEDGED.current()
            && self.has_configuration()
        {
            st.connection = Some(ConnectionState::Config);
            return vec![frame(current, &payload)];
        }

        if current == serverbound::play::ACCEPT_TELEPORTATION.current() {
            // Only the latest teleport counts, as on vanilla servers; Pumpkin kicks for a stale
            // one, which a switch or two quick teleports produce.
            let confirmed = (&payload[..]).get_var_int().ok().map(|id| id.0);
            if confirmed.is_none() || confirmed != st.teleport {
                return Vec::new();
            }
            st.teleport = None;
            return vec![frame(current, &payload)];
        }

        let mut out = Vec::with_capacity(2);
        let moves = [
            serverbound::play::MOVE_PLAYER_POS.current(),
            serverbound::play::MOVE_PLAYER_POS_ROT.current(),
            serverbound::play::MOVE_PLAYER_ROT.current(),
            serverbound::play::MOVE_PLAYER_STATUS_ONLY.current(),
        ];
        if moves.contains(&current) {
            // Before 1.9 the client doesn't confirm teleports; its first move after one is
            // where it landed, so confirm the teleport just before it.
            if self.version < JavaMinecraftVersion::V_1_9
                && let Some(teleport) = st.teleport.take()
            {
                out.push(frame(
                    serverbound::play::ACCEPT_TELEPORTATION.current(),
                    &accept_teleportation(teleport),
                ));
            }
            if let Some(rotation) = read_rotation(current, &payload) {
                st.rotation = rotation;
            }
        }
        out.push(frame(current, &payload));
        out
    }

    /// A packet from the backend, translated for the client.
    #[must_use]
    pub fn clientbound(&self, id: i32, payload: &[u8]) -> Translated {
        let mut st = self.lock();
        let state = st.connection.unwrap_or(ConnectionState::Play);
        if state != ConnectionState::Play {
            let to_client = PacketTranslator::translate_connection_outgoing(
                state_name(state),
                id,
                payload,
                self.version,
            )
            .into_iter()
            .collect();
            return Translated {
                to_client,
                to_backend: Vec::new(),
                play: false,
            };
        }

        let mut out = Translated {
            play: true,
            ..Translated::default()
        };
        if id == clientbound::play::LOGIN.current() {
            self.join(&mut st, payload, &mut out);
            return out;
        }
        if id == clientbound::play::START_CONFIGURATION.current() && !self.has_configuration() {
            debug!("Dropping start configuration for a {} client", self.version);
            return out;
        }
        if id == clientbound::play::CHUNK_BATCH_FINISHED.current() && !self.has_configuration() {
            out.to_backend.push(frame(
                serverbound::play::CHUNK_BATCH_RECEIVED.current(),
                &CHUNKS_PER_TICK.to_be_bytes(),
            ));
        }
        if id == clientbound::play::PLAYER_POSITION.current()
            && let Ok(teleport) = (&payload[..]).get_var_int()
        {
            st.teleport = Some(teleport.0);
        }
        if id == clientbound::play::PLAYER_INFO_UPDATE.current() {
            st.tab_list.extend(added_players(payload));
        } else if id == clientbound::play::PLAYER_INFO_REMOVE.current() {
            if let Ok(removed) = (&payload[..]).get_list(|read| read.get_uuid()) {
                for uuid in removed {
                    st.tab_list.remove(&uuid);
                }
            }
        } else if id == clientbound::play::BOSS_EVENT.current() {
            let mut cur = payload;
            if let (Ok(uuid), Ok(action)) = (cur.get_uuid(), cur.get_var_int()) {
                match action.0 {
                    0 => {
                        st.boss_bars.insert(uuid);
                    }
                    1 => {
                        st.boss_bars.remove(&uuid);
                    }
                    _ => {}
                }
            }
        }

        self.translate_play(id, payload, &mut out.to_client);
        out
    }

    /// Translates a 26.3 play packet into `out`, with the light packet older chunks need.
    fn translate_play(&self, id: i32, payload: &[u8], out: &mut Vec<(i32, Vec<u8>)>) {
        let version = self.version;
        let translated = entity_data::for_viewer(self.viewer, || {
            PacketTranslator::translate_outgoing_packet(id, payload, version)
        });
        match translated {
            Some(packet) => out.push(packet),
            None => {
                debug!("Dropping play packet {id} for a {version} client");
                return;
            }
        }
        if id == clientbound::play::LEVEL_CHUNK_WITH_LIGHT.current()
            && let Some(light) = chunk::light_from_current(payload, version)
            && let Some(light_id) = PacketTranslator::translate_clientbound_packet_id(
                clientbound::play::LIGHT_UPDATE.current(),
                version,
            )
        {
            out.push((light_id, light));
        }
    }

    /// The backend's join packet. Clients without configuration that already joined another
    /// server get the switch sequence: old tab list entries and boss bars removed, the join
    /// packet, then a respawn (through another dimension before 1.16) so the client drops the
    /// old world.
    fn join(&self, st: &mut State, payload: &[u8], out: &mut Translated) {
        let version = self.version;
        let switching = st.joined && !self.has_configuration();
        if switching {
            if !st.tab_list.is_empty() {
                let mut remove = Vec::new();
                let _ = remove.write_var_int(&VarInt(st.tab_list.len() as i32));
                for uuid in st.tab_list.drain() {
                    let _ = remove.write_uuid(&uuid);
                }
                self.translate_play(
                    clientbound::play::PLAYER_INFO_REMOVE.current(),
                    &remove,
                    &mut out.to_client,
                );
            }
            for uuid in st.boss_bars.drain() {
                let mut remove = Vec::new();
                let _ = remove.write_uuid(&uuid);
                let _ = remove.write_var_int(&VarInt(1));
                self.translate_play(
                    clientbound::play::BOSS_EVENT.current(),
                    &remove,
                    &mut out.to_client,
                );
            }
        }
        st.tab_list.clear();
        st.boss_bars.clear();

        // Entity ids are per server: start over with this one's.
        entity_data::forget_viewer(self.viewer);
        entity_data::join_viewer(self.viewer);
        let before = out.to_client.len();
        self.translate_play(
            clientbound::play::LOGIN.current(),
            payload,
            &mut out.to_client,
        );
        if out.to_client.len() == before {
            return;
        }
        if let Some(tags) = tags::join_tags(version)
            && let Some(id) = PacketTranslator::translate_clientbound_packet_id(
                clientbound::play::UPDATE_TAGS.current(),
                version,
            )
        {
            out.to_client.push((id, tags));
        }
        if switching && let Some(spawn) = join_spawn_data(payload) {
            if version < JavaMinecraftVersion::V_1_16 {
                let mut elsewhere = spawn.clone();
                elsewhere.dimension = if spawn.dimension == Dimension::OVERWORLD {
                    Dimension::THE_NETHER
                } else {
                    Dimension::OVERWORLD
                };
                self.respawn(elsewhere, &mut out.to_client);
            }
            self.respawn(spawn, &mut out.to_client);
        }
        st.joined = true;
        st.awaiting_join = false;
    }

    fn respawn(&self, spawn: PlayerSpawnData, out: &mut Vec<(i32, Vec<u8>)>) {
        let mut payload = Vec::new();
        if CRespawn::new(spawn, CRespawn::KEEP_NOTHING)
            .write_packet_data(&mut payload, &CURRENT_MC_VERSION)
            .is_ok()
        {
            self.translate_play(clientbound::play::RESPAWN.current(), &payload, out);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        entity_data::forget_viewer(self.viewer);
    }
}

/// The spawn data of a 26.3 join packet.
fn join_spawn_data(mut payload: &[u8]) -> Option<PlayerSpawnData> {
    payload.get_i32_be().ok()?; // entity id
    payload.get_bool().ok()?; // hardcore
    payload.get_list(|read| read.get_str().map(drop)).ok()?; // dimension names
    payload.get_var_int().ok()?; // max players
    payload.get_var_int().ok()?; // view distance
    payload.get_var_int().ok()?; // simulation distance
    payload.get_bool().ok()?; // reduced debug info
    payload.get_bool().ok()?; // respawn screen
    payload.get_bool().ok()?; // limited crafting
    PlayerSpawnData::read(&mut payload, &CURRENT_MC_VERSION).ok()
}

/// The 26.3 payload of a teleport confirmation: the id, then position and rotation, which
/// Pumpkin doesn't read.
fn accept_teleportation(teleport: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + 32);
    let _ = out.write_var_int(&VarInt(teleport));
    out.extend_from_slice(&[0; 3 * 8 + 2 * 4]);
    out
}

/// Yaw and pitch of a 26.3 movement packet that has them.
fn read_rotation(id: i32, mut payload: &[u8]) -> Option<(f32, f32)> {
    if id == serverbound::play::MOVE_PLAYER_POS_ROT.current() {
        payload = payload.get(24..)?;
    } else if id != serverbound::play::MOVE_PLAYER_ROT.current() {
        return None;
    }
    Some((payload.get_f32_be().ok()?, payload.get_f32_be().ok()?))
}

/// Players a 26.3 `PLAYER_INFO_UPDATE` adds to the tab list.
fn added_players(mut payload: &[u8]) -> Vec<Uuid> {
    let Ok(bits) = payload.get_u8() else {
        return Vec::new();
    };
    let flags = PlayerInfoFlags::from_bits_retain(bits);
    if !flags.contains(PlayerInfoFlags::ADD_PLAYER) {
        return Vec::new();
    }
    let entry = |read: &mut &[u8]| -> Option<Uuid> {
        let uuid = read.get_uuid().ok()?;
        read.get_str().ok()?;
        read.get_list(|read| {
            read.get_str()?;
            read.get_str()?;
            read.get_option(|read| read.get_str())?;
            Ok(())
        })
        .ok()?;
        if flags.contains(PlayerInfoFlags::INITIALIZE_CHAT) {
            read.get_option(|read| {
                read.get_uuid()?;
                read.get_i64_be()?;
                let key = read.get_var_int()?.0 as usize;
                read.read_slice_borrowed(key)?;
                let signature = read.get_var_int()?.0 as usize;
                read.read_slice_borrowed(signature)?;
                Ok(())
            })
            .ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_GAME_MODE) {
            read.get_var_int().ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_LISTED) {
            read.get_bool().ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_LATENCY) {
            read.get_var_int().ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_DISPLAY_NAME) {
            read.get_option(|read| read.get_component(&CURRENT_MC_VERSION))
                .ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_LIST_PRIORITY) {
            read.get_var_int().ok()?;
        }
        if flags.contains(PlayerInfoFlags::UPDATE_HAT) {
            read.get_bool().ok()?;
        }
        Some(uuid)
    };
    let Ok(count) = payload.get_var_int() else {
        return Vec::new();
    };
    let mut players = Vec::new();
    for _ in 0..count.0.clamp(0, 1024) {
        match entry(&mut payload) {
            Some(uuid) => players.push(uuid),
            None => break,
        }
    }
    players
}
