use std::fmt::Debug;

use tfhe::integer::{RadixCiphertext, ServerKey as IntegerServerKey};

use crate::client_key::Key;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerKey {
    pub(crate) k: IntegerServerKey,
    pub(crate) num_blocks: usize,
    pub(crate) msg_mod: usize,
}

impl Debug for ServerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerKey").finish()
    }
}

impl ServerKey {
    /// Returns an encryption of zero.
    pub fn create_zero(&self) -> RadixCiphertext {
        self.k
            .create_trivial_zero_radix::<RadixCiphertext>(self.num_blocks)
    }

    /// Returns an encryption of one.
    pub fn create_one(&self) -> RadixCiphertext {
        self.k
            .create_trivial_radix::<u8, RadixCiphertext>(1, self.num_blocks)
    }

    /// Returns an encryption of the specified value.
    pub fn create_value(&self, v: u64) -> RadixCiphertext {
        self.k
            .create_trivial_radix::<u64, RadixCiphertext>(v, self.num_blocks)
    }
}

impl Key for ServerKey {
    fn max_int(&self) -> usize {
        self.msg_mod.pow(self.num_blocks as u32) - 1
    }
}
