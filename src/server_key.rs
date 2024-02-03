//! This module covers the server key that is used for operating on encrypted
//! strings.

use std::fmt::Debug;

use tfhe::integer::ServerKey as IntegerServerKey;

use crate::client_key::Key;

/// A key used by the server for operations on encrypted strings.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerKey {
    pub(crate) k: IntegerServerKey,
    pub(crate) msg_mod: usize,
    pub(crate) num_blocks_char: usize,
    pub(crate) num_blocks_usize: usize,
}

impl Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerKey").finish()
    }
}

impl Key for ServerKey {
    fn msg_mod(&self) -> usize {
        self.msg_mod
    }

    fn num_blocks_usize(&self) -> usize {
        self.num_blocks_usize
    }
}
