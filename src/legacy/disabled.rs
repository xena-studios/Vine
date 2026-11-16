//! Without the `legacy-clients` feature nothing is translated: [`Session::new`] never returns a
//! session, and backends speak the client's version.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use pumpkin_protocol::ConnectionState;
use pumpkin_util::version::JavaMinecraftVersion;

use super::Translated;

/// Never constructed.
pub struct Session {
    never: Infallible,
}

impl Session {
    #[must_use]
    pub fn new(_version: JavaMinecraftVersion, _player: uuid::Uuid) -> Option<Arc<Self>> {
        None
    }

    pub fn reset(&self, _state: ConnectionState) {
        match self.never {}
    }

    pub fn begin_switch(&self) {
        match self.never {}
    }

    #[must_use]
    pub fn login_success(&self, _packet: &[u8]) -> Option<Bytes> {
        match self.never {}
    }

    #[must_use]
    pub fn serverbound(&self, _id: i32, _payload: &[u8]) -> Vec<Bytes> {
        match self.never {}
    }

    #[must_use]
    pub fn clientbound(&self, _id: i32, _payload: &[u8]) -> Translated {
        match self.never {}
    }
}
