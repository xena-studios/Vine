//! Per-player packet timing for anticheat plugins.
//!
//! Vine reads every packet a client sends, in order, so it is the place to time them. A plugin
//! call per packet costs too much (a WASM call per packet froze Pumpkin in load tests), so this
//! module measures natively and plugins collect the results in one call per window
//! (`packet-timing.take-packet-timing`). Off unless `[packet_timing] enabled = true`.
//!
//! Packets are classified in the version the backend speaks (the current one for translated
//! clients), so one set of packet layouts covers every client version.
//!
//! | Metric | Meaning |
//! |---|---|
//! | `packets` | Packets the client sent in the window |
//! | `packets_per_second_max` | Most packets within any one second |
//! | `swings` | Arm swings (left clicks) |
//! | `cps_max` | Most swings within any one second |
//! | `swing_intervals` | Gaps between two swings under one second apart, the ones the next two use |
//! | `swing_interval_mean_ms` | Mean of those gaps; only with at least two |
//! | `swing_interval_stddev_ms` | Their standard deviation: a clicker's gaps hardly vary; only with at least two |
//! | `attacks` | Attack packets |
//! | `attacks_per_second_max` | Most attacks within any one second |
//! | `rotations` | Packets carrying a rotation |
//! | `rotation_snaps` | Rotations that turned at least [`SNAP_DEGREES`] from the previous one |
//! | `rotation_delta_max` | Largest turn in one packet, degrees |
//! | `moves` | Movement packets (position, rotation or ground status) |
//! | `moves_per_second_max` | Most movement packets within any one second |
//! | `ticks` | Client ticks: tick-end packets from 1.21.2, movement packets up to 1.8 (sent every tick); none for 1.9 to 1.21.1 |
//! | `timer_balance_max_ms` | How far the client's ticks got ahead of real time, ms (a timer cheat runs them faster); only when ticks were seen |
//! | `air_rise_max` | Most height gained in one run of movement packets off the ground, blocks |
//! | `hover_ms_max` | Longest time off the ground without falling, ms |
//!
//! Air time trusts the client's on-ground flag and skips time the client says it is flying
//! (creative or spectator flight); a teleport or server switch starts a new run. Vine can't see
//! blocks, so ladders, water, levitation, elytra and bounces look like air time too: plugins
//! should judge these with that in mind.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use pumpkin_protocol::java::server::play::{
    SAttack, SClientTickEnd, SPlayerAbilities, SPlayerPosition, SPlayerPositionRotation,
    SPlayerRotation, SSetPlayerGround, SSwingArm,
};
use pumpkin_protocol::ser::NetworkReadExt;
use pumpkin_protocol::{ConnectionState, ServerPacket};
use pumpkin_util::version::JavaMinecraftVersion;
use uuid::Uuid;

use crate::protocol;

/// A rotation of at least this many degrees in one packet counts as a snap.
pub const SNAP_DEGREES: f32 = 45.0;
/// One client tick at 20 ticks per second.
const TICK_MS: f64 = 50.0;
/// How far behind real time the tick balance may fall. Ticks held back by a lag spike arrive
/// together afterwards; this much lag is forgiven, and no more can be banked.
const LAG_ALLOWANCE_MS: f64 = 3000.0;
const SECOND_MS: u64 = 1000;

/// What a serverbound packet means for timing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Serverbound {
    Attack,
    Swing,
    /// A movement packet; `position` and `rotation` when it carries them.
    Move {
        position: Option<(f64, f64, f64)>,
        rotation: Option<(f32, f32)>,
        on_ground: bool,
    },
    TickEnd,
    /// The client started or stopped flying (creative or spectator flight).
    Abilities {
        flying: bool,
    },
    Other,
}

/// Serverbound play packet ids in one version.
#[derive(Clone, Copy, Debug)]
pub struct PacketIds {
    version: JavaMinecraftVersion,
    attack: Option<i32>,
    swing: Option<i32>,
    position: Option<i32>,
    position_rotation: Option<i32>,
    rotation: Option<i32>,
    status: Option<i32>,
    tick_end: Option<i32>,
    abilities: Option<i32>,
}

impl PacketIds {
    /// Ids for packets in `version`, the version the backend speaks.
    #[must_use]
    pub fn new(version: JavaMinecraftVersion) -> Self {
        let play = ConnectionState::Play;
        Self {
            version,
            attack: protocol::serverbound_id::<SAttack>(play, version),
            swing: protocol::serverbound_id::<SSwingArm>(play, version),
            position: protocol::serverbound_id::<SPlayerPosition>(play, version),
            position_rotation: protocol::serverbound_id::<SPlayerPositionRotation>(play, version),
            rotation: protocol::serverbound_id::<SPlayerRotation>(play, version),
            status: protocol::serverbound_id::<SSetPlayerGround>(play, version),
            tick_end: protocol::serverbound_id::<SClientTickEnd>(play, version),
            abilities: protocol::serverbound_id::<SPlayerAbilities>(play, version),
        }
    }

    /// What the packet `id` with `payload` is. Unreadable packets are [`Serverbound::Other`].
    #[must_use]
    pub fn classify(&self, id: i32, payload: &[u8]) -> Serverbound {
        let id = Some(id);
        let version = &self.version;
        let mut payload = payload;
        let on_ground = |flags: u8| flags & 0x01 != 0;
        if id == self.position {
            SPlayerPosition::read(&mut payload, version).map_or(Serverbound::Other, |p| {
                Serverbound::Move {
                    position: Some((p.position.x, p.position.y, p.position.z)),
                    rotation: None,
                    on_ground: on_ground(p.collision),
                }
            })
        } else if id == self.position_rotation {
            SPlayerPositionRotation::read(&mut payload, version).map_or(Serverbound::Other, |p| {
                Serverbound::Move {
                    position: Some((p.position.x, p.position.y, p.position.z)),
                    rotation: Some((p.yaw, p.pitch)),
                    on_ground: on_ground(p.collision),
                }
            })
        } else if id == self.rotation {
            SPlayerRotation::read(&mut payload, version).map_or(Serverbound::Other, |p| {
                Serverbound::Move {
                    position: None,
                    rotation: Some((p.yaw, p.pitch)),
                    on_ground: p.ground,
                }
            })
        } else if id == self.status {
            SSetPlayerGround::read(&mut payload, version).map_or(Serverbound::Other, |p| {
                Serverbound::Move {
                    position: None,
                    rotation: None,
                    on_ground: p.on_ground,
                }
            })
        } else if id == self.attack {
            Serverbound::Attack
        } else if id == self.swing {
            Serverbound::Swing
        } else if id == self.tick_end {
            Serverbound::TickEnd
        } else if id == self.abilities {
            SPlayerAbilities::read(&mut payload, version).map_or(Serverbound::Other, |p| {
                Serverbound::Abilities {
                    flying: p.is_flying(),
                }
            })
        } else {
            Serverbound::Other
        }
    }
}

/// Which packets mark a client tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickSource {
    /// Tick-end packets (1.21.2 and later).
    TickEnd,
    /// Movement packets, which clients up to 1.8 send every tick.
    Movement,
    /// Neither: 1.9 to 1.21.1 send movement only when something changed.
    None,
}

impl TickSource {
    #[must_use]
    pub fn for_client(version: JavaMinecraftVersion) -> Self {
        if version == JavaMinecraftVersion::Unknown || version >= JavaMinecraftVersion::V_1_21_2 {
            Self::TickEnd
        } else if version <= JavaMinecraftVersion::V_1_8 {
            Self::Movement
        } else {
            Self::None
        }
    }
}

/// Counts events and keeps the most within any one second.
#[derive(Default)]
struct Rate {
    total: u32,
    recent: VecDeque<u64>,
    max: u32,
}

impl Rate {
    fn record(&mut self, now_ms: u64) {
        self.total += 1;
        while self
            .recent
            .front()
            .is_some_and(|&at| at + SECOND_MS <= now_ms)
        {
            self.recent.pop_front();
        }
        self.recent.push_back(now_ms);
        self.max = self
            .max
            .max(u32::try_from(self.recent.len()).unwrap_or(u32::MAX));
    }

    /// A new window; the last second still counts towards its first second.
    fn reset(&mut self) {
        self.total = 0;
        self.max = 0;
    }
}

/// Running mean and variance (Welford).
#[derive(Default)]
struct Spread {
    count: u32,
    mean: f64,
    m2: f64,
}

impl Spread {
    fn add(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / f64::from(self.count);
        self.m2 += delta * (value - self.mean);
    }

    fn stddev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / f64::from(self.count - 1)).sqrt()
        }
    }
}

/// One player's timing. Times are milliseconds on a monotonic clock.
pub struct Recorder {
    protocol: u32,
    ticks_from: TickSource,
    window_start_ms: u64,
    left: bool,

    packets: Rate,
    swings: Rate,
    attacks: Rate,
    moves: Rate,
    last_swing_ms: Option<u64>,
    swing_gaps: Spread,

    rotations: u32,
    rotation_snaps: u32,
    rotation_delta_max: f32,
    last_rotation: Option<(f32, f32)>,

    ticks: u32,
    last_tick_ms: Option<u64>,
    /// Client time ahead of real time, ms; negative when behind.
    balance_ms: f64,
    balance_max_ms: Option<f64>,

    flying: bool,
    last_y: Option<f64>,
    /// Height the current air run started from, once off the ground.
    air_from_y: Option<f64>,
    /// When the current run of not falling in the air started.
    hover_since_ms: Option<u64>,
    air_rise_max: f64,
    hover_ms_max: u64,
}

impl Recorder {
    #[must_use]
    pub fn new(protocol: u32, ticks_from: TickSource, now_ms: u64) -> Self {
        Self {
            protocol,
            ticks_from,
            window_start_ms: now_ms,
            left: false,
            packets: Rate::default(),
            swings: Rate::default(),
            attacks: Rate::default(),
            moves: Rate::default(),
            last_swing_ms: None,
            swing_gaps: Spread::default(),
            rotations: 0,
            rotation_snaps: 0,
            rotation_delta_max: 0.0,
            last_rotation: None,
            ticks: 0,
            last_tick_ms: None,
            balance_ms: 0.0,
            balance_max_ms: None,
            flying: false,
            last_y: None,
            air_from_y: None,
            hover_since_ms: None,
            air_rise_max: 0.0,
            hover_ms_max: 0,
        }
    }

    /// Any packet from the client, before Vine handles or translates it.
    pub fn packet(&mut self, now_ms: u64) {
        self.packets.record(now_ms);
    }

    /// A packet as the backend will see it.
    pub fn serverbound(&mut self, packet: Serverbound, now_ms: u64) {
        match packet {
            Serverbound::Attack => self.attacks.record(now_ms),
            Serverbound::Swing => {
                self.swings.record(now_ms);
                if let Some(last) = self.last_swing_ms {
                    let gap = now_ms.saturating_sub(last);
                    if gap < SECOND_MS {
                        self.swing_gaps.add(gap as f64);
                    }
                }
                self.last_swing_ms = Some(now_ms);
            }
            Serverbound::Move {
                position,
                rotation,
                on_ground,
            } => {
                self.moves.record(now_ms);
                if let Some(rotation) = rotation {
                    self.rotated(rotation);
                }
                self.moved(position.map(|p| p.1), on_ground, now_ms);
                if self.ticks_from == TickSource::Movement {
                    self.tick(now_ms);
                }
            }
            Serverbound::TickEnd => {
                if self.ticks_from == TickSource::TickEnd {
                    self.tick(now_ms);
                }
            }
            Serverbound::Abilities { flying } => {
                self.flying = flying;
                self.land();
            }
            Serverbound::Other => {}
        }
    }

    fn rotated(&mut self, (yaw, pitch): (f32, f32)) {
        self.rotations += 1;
        if let Some((last_yaw, last_pitch)) = self.last_rotation {
            // Yaw isn't wrapped by the client; the turn is the shortest way round.
            let dyaw = (yaw - last_yaw + 180.0).rem_euclid(360.0) - 180.0;
            let delta = dyaw.hypot(pitch - last_pitch);
            if delta.is_finite() {
                self.rotation_delta_max = self.rotation_delta_max.max(delta);
                if delta >= SNAP_DEGREES {
                    self.rotation_snaps += 1;
                }
            }
        }
        self.last_rotation = Some((yaw, pitch));
    }

    fn moved(&mut self, y: Option<f64>, on_ground: bool, now_ms: u64) {
        if on_ground || self.flying {
            self.land();
            if let Some(y) = y {
                self.last_y = Some(y);
            }
            return;
        }
        let from = *self
            .air_from_y
            .get_or_insert_with(|| self.last_y.or(y).unwrap_or(0.0));
        let falling = match (y, self.last_y) {
            (Some(y), Some(last)) => y < last - 1e-4,
            _ => false,
        };
        if let Some(y) = y {
            self.air_rise_max = self.air_rise_max.max(y - from);
            self.last_y = Some(y);
        }
        if falling {
            self.hover_since_ms = None;
        } else {
            let since = *self.hover_since_ms.get_or_insert(now_ms);
            self.hover_ms_max = self.hover_ms_max.max(now_ms.saturating_sub(since));
        }
    }

    /// Back on the ground, or flying: the air run ends.
    fn land(&mut self) {
        self.air_from_y = None;
        self.hover_since_ms = None;
    }

    /// The server moved the player (a teleport, a server switch): the next position isn't a move.
    pub fn teleported(&mut self) {
        self.land();
        self.last_y = None;
        self.last_rotation = None;
    }

    fn tick(&mut self, now_ms: u64) {
        self.ticks += 1;
        if let Some(last) = self.last_tick_ms {
            self.balance_ms -= now_ms.saturating_sub(last) as f64;
            self.balance_ms = self.balance_ms.max(-LAG_ALLOWANCE_MS);
            self.balance_max_ms = Some(
                self.balance_max_ms
                    .map_or(self.balance_ms, |max| max.max(self.balance_ms)),
            );
        }
        self.balance_ms += TICK_MS;
        self.last_tick_ms = Some(now_ms);
    }

    /// Ends the window: its metrics, then counts start again. State that spans windows (the
    /// tick balance, the current air run, the last rotation) carries on.
    pub fn flush(&mut self, now_ms: u64) -> PacketTimingSample {
        let window_ms = now_ms.saturating_sub(self.window_start_ms);
        let mut metrics = vec![
            ("packets", f64::from(self.packets.total)),
            ("packets_per_second_max", f64::from(self.packets.max)),
            ("swings", f64::from(self.swings.total)),
            ("cps_max", f64::from(self.swings.max)),
            ("swing_intervals", f64::from(self.swing_gaps.count)),
            ("attacks", f64::from(self.attacks.total)),
            ("attacks_per_second_max", f64::from(self.attacks.max)),
            ("rotations", f64::from(self.rotations)),
            ("rotation_snaps", f64::from(self.rotation_snaps)),
            (
                "rotation_delta_max",
                round(f64::from(self.rotation_delta_max)),
            ),
            ("moves", f64::from(self.moves.total)),
            ("moves_per_second_max", f64::from(self.moves.max)),
            ("ticks", f64::from(self.ticks)),
            ("air_rise_max", round(self.air_rise_max)),
            ("hover_ms_max", self.hover_ms_max as f64),
        ];
        if self.swing_gaps.count >= 2 {
            metrics.push(("swing_interval_mean_ms", round(self.swing_gaps.mean)));
            metrics.push(("swing_interval_stddev_ms", round(self.swing_gaps.stddev())));
        }
        if let Some(balance) = self.balance_max_ms {
            metrics.push(("timer_balance_max_ms", balance.round()));
        }
        let sample = PacketTimingSample {
            uuid: Uuid::nil(),
            protocol: self.protocol,
            window_ms,
            metrics: metrics
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
        };

        self.window_start_ms = now_ms;
        self.packets.reset();
        self.swings.reset();
        self.attacks.reset();
        self.moves.reset();
        self.swing_gaps = Spread::default();
        self.rotations = 0;
        self.rotation_snaps = 0;
        self.rotation_delta_max = 0.0;
        self.ticks = 0;
        self.balance_max_ms = None;
        self.air_rise_max = 0.0;
        self.hover_ms_max = 0;
        // A run still going counts again from here.
        if self.hover_since_ms.is_some() {
            self.hover_since_ms = Some(now_ms);
        }
        if self.air_from_y.is_some() {
            self.air_from_y = self.last_y;
        }
        sample
    }
}

/// Three decimal places.
fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Locks a player's recorder, even if a panic poisoned it.
pub fn lock(timing: &PlayerTiming) -> std::sync::MutexGuard<'_, Recorder> {
    timing.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The id and payload of a framed packet (`legacy::frame`).
#[must_use]
pub fn split_frame(frame: &[u8]) -> Option<(i32, &[u8])> {
    let mut rest = frame;
    let id = rest.get_var_int().ok()?;
    Some((id.0, rest))
}

/// One player's window, as plugins get it.
#[derive(Clone, Debug, PartialEq)]
pub struct PacketTimingSample {
    pub uuid: Uuid,
    pub protocol: u32,
    pub window_ms: u64,
    pub metrics: Vec<(String, f64)>,
}

/// A player's recorder, shared by their connection and [`PacketTimings`].
pub type PlayerTiming = Arc<Mutex<Recorder>>;

/// Every player's recorder. Lives in the [`SessionManager`](crate::session::SessionManager).
pub struct PacketTimings {
    clock: Instant,
    players: Mutex<HashMap<Uuid, PlayerTiming>>,
}

impl Default for PacketTimings {
    fn default() -> Self {
        Self {
            clock: Instant::now(),
            players: Mutex::new(HashMap::new()),
        }
    }
}

impl PacketTimings {
    /// Milliseconds since the proxy started.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Starts timing a player who joined. Logging in again replaces the old recorder.
    pub fn start(&self, uuid: Uuid, client: JavaMinecraftVersion) -> PlayerTiming {
        let protocol = u32::try_from(client.protocol_version()).unwrap_or(0);
        let timing = Arc::new(Mutex::new(Recorder::new(
            protocol,
            TickSource::for_client(client),
            self.now_ms(),
        )));
        self.players
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(uuid, timing.clone());
        timing
    }

    /// The player left; their last window is still taken once.
    pub fn end(&self, uuid: Uuid, timing: &PlayerTiming) {
        let players = self.players.lock().unwrap_or_else(PoisonError::into_inner);
        if players.get(&uuid).is_some_and(|t| Arc::ptr_eq(t, timing)) {
            timing.lock().unwrap_or_else(PoisonError::into_inner).left = true;
        }
    }

    /// Ends every player's window and returns them; players who left are forgotten.
    pub fn take(&self) -> Vec<PacketTimingSample> {
        let now = self.now_ms();
        let mut players = self.players.lock().unwrap_or_else(PoisonError::into_inner);
        let mut samples = Vec::with_capacity(players.len());
        players.retain(|uuid, timing| {
            let mut recorder = timing.lock().unwrap_or_else(PoisonError::into_inner);
            let mut sample = recorder.flush(now);
            sample.uuid = *uuid;
            samples.push(sample);
            !recorder.left
        });
        samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pumpkin_data::packet::CURRENT_MC_VERSION;

    fn metric(sample: &PacketTimingSample, name: &str) -> Option<f64> {
        sample
            .metrics
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }

    fn walk(y: f64, on_ground: bool) -> Serverbound {
        Serverbound::Move {
            position: Some((0.0, y, 0.0)),
            rotation: None,
            on_ground,
        }
    }

    fn look(yaw: f32, pitch: f32) -> Serverbound {
        Serverbound::Move {
            position: None,
            rotation: Some((yaw, pitch)),
            on_ground: true,
        }
    }

    #[test]
    fn counts_packets_swings_and_attacks_per_second() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        for i in 0..30 {
            r.packet(i * 10);
        }
        for i in 0..12 {
            r.serverbound(Serverbound::Swing, 2_000 + i * 80);
        }
        r.serverbound(Serverbound::Attack, 2_000);
        r.serverbound(Serverbound::Attack, 2_500);
        let s = r.flush(30_000);
        assert_eq!(s.window_ms, 30_000);
        assert_eq!(metric(&s, "packets"), Some(30.0));
        assert_eq!(metric(&s, "packets_per_second_max"), Some(30.0));
        assert_eq!(metric(&s, "swings"), Some(12.0));
        assert_eq!(metric(&s, "cps_max"), Some(12.0));
        assert_eq!(metric(&s, "swing_intervals"), Some(11.0));
        assert_eq!(metric(&s, "swing_interval_mean_ms"), Some(80.0));
        assert_eq!(metric(&s, "swing_interval_stddev_ms"), Some(0.0));
        assert_eq!(metric(&s, "attacks"), Some(2.0));
        assert_eq!(metric(&s, "attacks_per_second_max"), Some(2.0));
        // Counts start again; no ticks, so no timer balance.
        let s = r.flush(60_000);
        assert_eq!(metric(&s, "swings"), Some(0.0));
        assert_eq!(metric(&s, "swing_interval_mean_ms"), None);
        assert_eq!(metric(&s, "timer_balance_max_ms"), None);
    }

    #[test]
    fn swing_gaps_over_a_second_are_not_clicking() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        for at in [0, 100, 5_000, 5_150] {
            r.serverbound(Serverbound::Swing, at);
        }
        let s = r.flush(30_000);
        assert_eq!(metric(&s, "swing_intervals"), Some(2.0));
        assert_eq!(metric(&s, "swing_interval_mean_ms"), Some(125.0));
        assert!((metric(&s, "swing_interval_stddev_ms").unwrap() - 35.355).abs() < 1e-3);
    }

    #[test]
    fn steady_ticks_keep_the_balance_at_zero() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        for i in 0..200 {
            r.serverbound(Serverbound::TickEnd, i * 50);
        }
        let s = r.flush(10_000);
        assert_eq!(metric(&s, "ticks"), Some(200.0));
        assert_eq!(metric(&s, "timer_balance_max_ms"), Some(0.0));
    }

    #[test]
    fn a_fast_timer_runs_ahead() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        // 1.5 times normal speed for 3 seconds: 90 ticks, 33 ms apart.
        for i in 0..90 {
            r.serverbound(Serverbound::TickEnd, i * 100 / 3);
        }
        let balance = metric(&r.flush(3_000), "timer_balance_max_ms").unwrap();
        assert!(balance > 1_400.0, "{balance}");
    }

    #[test]
    fn ticks_after_a_lag_spike_are_forgiven() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        let mut at = 0;
        for _ in 0..20 {
            r.serverbound(Serverbound::TickEnd, at);
            at += 50;
        }
        // Two seconds without packets, then the 40 held-back ticks at once.
        at += 2_000;
        for _ in 0..40 {
            r.serverbound(Serverbound::TickEnd, at);
        }
        for _ in 0..20 {
            at += 50;
            r.serverbound(Serverbound::TickEnd, at);
        }
        let balance = metric(&r.flush(at), "timer_balance_max_ms").unwrap();
        assert!(balance <= 100.0, "{balance}");
    }

    #[test]
    fn old_clients_tick_with_movement() {
        let mut r = Recorder::new(47, TickSource::for_client(JavaMinecraftVersion::V_1_8), 0);
        for i in 0..40 {
            r.serverbound(walk(64.0, true), i * 50);
            // Ignored as a tick source for 1.8.
            r.serverbound(Serverbound::TickEnd, i * 50);
        }
        let s = r.flush(2_000);
        assert_eq!(metric(&s, "ticks"), Some(40.0));
        assert_eq!(metric(&s, "moves"), Some(40.0));
        assert_eq!(
            TickSource::for_client(JavaMinecraftVersion::V_1_12_2),
            TickSource::None
        );
        assert_eq!(
            TickSource::for_client(JavaMinecraftVersion::V_1_21_2),
            TickSource::TickEnd
        );
    }

    #[test]
    fn rotation_snaps_take_the_short_way_round() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        r.serverbound(look(170.0, 0.0), 0);
        // 170 to -170 is a 20 degree turn, not 340.
        r.serverbound(look(-170.0, 0.0), 50);
        r.serverbound(look(-100.0, 30.0), 100);
        r.serverbound(look(-100.0, 31.0), 150);
        let s = r.flush(1_000);
        assert_eq!(metric(&s, "rotations"), Some(4.0));
        assert_eq!(metric(&s, "rotation_snaps"), Some(1.0));
        assert!((metric(&s, "rotation_delta_max").unwrap() - 76.158).abs() < 1e-3);
        assert_eq!(metric(&s, "moves"), Some(4.0));
    }

    #[test]
    fn a_jump_is_short_air_time() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        r.serverbound(walk(64.0, true), 0);
        // Vanilla jump: up 1.25 blocks over 6 ticks, then down.
        let arc = [
            0.42, 0.753, 1.001, 1.167, 1.249, 1.249, 1.17, 1.015, 0.787, 0.489, 0.123,
        ];
        for (i, rise) in arc.iter().enumerate() {
            r.serverbound(walk(64.0 + rise, false), 50 * (i as u64 + 1));
        }
        r.serverbound(walk(64.0, true), 600);
        let s = r.flush(1_000);
        assert!((metric(&s, "air_rise_max").unwrap() - 1.249).abs() < 1e-9);
        assert_eq!(metric(&s, "hover_ms_max"), Some(250.0));
    }

    #[test]
    fn hovering_and_climbing_in_the_air() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        r.serverbound(walk(64.0, true), 0);
        for i in 1..=60 {
            r.serverbound(walk(64.0 + f64::from(i as u32) * 0.1, false), i * 50);
        }
        let s = r.flush(3_000);
        assert!((metric(&s, "air_rise_max").unwrap() - 6.0).abs() < 1e-9);
        assert_eq!(metric(&s, "hover_ms_max"), Some(2_950.0));
        // Still up there: the run carries on into the next window, counted from its start.
        for i in 61..=80 {
            r.serverbound(walk(70.0, false), i * 50);
        }
        let s = r.flush(4_000);
        assert_eq!(metric(&s, "hover_ms_max"), Some(1_000.0));
    }

    #[test]
    fn declared_flight_and_teleports_are_not_air_time() {
        let mut r = Recorder::new(777, TickSource::TickEnd, 0);
        r.serverbound(walk(64.0, true), 0);
        r.serverbound(Serverbound::Abilities { flying: true }, 10);
        for i in 1..=40 {
            r.serverbound(walk(64.0 + f64::from(i as u32), false), i * 50);
        }
        r.serverbound(Serverbound::Abilities { flying: false }, 2_100);
        r.teleported();
        r.serverbound(walk(200.0, false), 2_150);
        r.serverbound(walk(199.9, false), 2_200);
        let s = r.flush(3_000);
        assert_eq!(metric(&s, "air_rise_max"), Some(0.0));
        assert_eq!(metric(&s, "hover_ms_max"), Some(0.0));
    }

    #[test]
    fn the_registry_keeps_a_leaver_for_one_take() {
        let timings = PacketTimings::default();
        let alex = Uuid::from_u128(1);
        let timing = timings.start(alex, JavaMinecraftVersion::V_1_8);
        timing.lock().unwrap().serverbound(Serverbound::Swing, 0);
        timings.end(alex, &timing);
        let samples = timings.take();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].uuid, alex);
        assert_eq!(samples[0].protocol, 47);
        assert_eq!(metric(&samples[0], "swings"), Some(1.0));
        assert!(timings.take().is_empty());
    }

    #[test]
    fn a_new_login_isnt_ended_by_the_old_connection() {
        let timings = PacketTimings::default();
        let alex = Uuid::from_u128(1);
        let old = timings.start(alex, CURRENT_MC_VERSION);
        let new = timings.start(alex, CURRENT_MC_VERSION);
        timings.end(alex, &old);
        assert_eq!(timings.take().len(), 1);
        assert_eq!(timings.take().len(), 1);
        timings.end(alex, &new);
        assert_eq!(timings.take().len(), 1);
        assert!(timings.take().is_empty());
    }

    #[test]
    fn classifies_current_packets() {
        use pumpkin_protocol::ClientPacket;
        use pumpkin_util::math::vector3::Vector3;
        let ids = PacketIds::new(CURRENT_MC_VERSION);
        let body = |packet: &dyn Fn(&mut Vec<u8>)| {
            let mut buf = Vec::new();
            packet(&mut buf);
            buf
        };
        let pos = body(&|buf| {
            SPlayerPositionRotation {
                position: Vector3::new(1.0, 2.0, 3.0),
                yaw: 90.0,
                pitch: -10.0,
                collision: 1,
            }
            .write_packet_data(buf, &CURRENT_MC_VERSION)
            .unwrap();
        });
        assert_eq!(
            ids.classify(ids.position_rotation.unwrap(), &pos),
            Serverbound::Move {
                position: Some((1.0, 2.0, 3.0)),
                rotation: Some((90.0, -10.0)),
                on_ground: true,
            }
        );
        assert_eq!(
            ids.classify(ids.tick_end.unwrap(), &[]),
            Serverbound::TickEnd
        );
        assert_eq!(ids.classify(ids.swing.unwrap(), &[]), Serverbound::Swing);
        assert_eq!(ids.classify(ids.attack.unwrap(), &[5]), Serverbound::Attack);
        assert_eq!(
            ids.classify(ids.abilities.unwrap(), &[0x02]),
            Serverbound::Abilities { flying: true }
        );
        // Truncated: not a move.
        assert_eq!(
            ids.classify(ids.position.unwrap(), &[0; 4]),
            Serverbound::Other
        );
    }
}
