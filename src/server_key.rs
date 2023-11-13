use std::fmt::Debug;

use tfhe::integer::{
    block_decomposition::DecomposableInto, RadixCiphertext, ServerKey as IntegerServerKey,
};

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
    /// Returns a trivial ciphertext with value `0`.
    pub fn create_zero(&self) -> RadixCiphertext {
        self.k
            .create_trivial_zero_radix::<RadixCiphertext>(self.num_blocks)
    }

    /// Returns a trivial ciphertext with value `1`.
    pub fn create_one(&self) -> RadixCiphertext {
        self.k
            .create_trivial_radix::<u8, RadixCiphertext>(1, self.num_blocks)
    }

    /// Returns a trivial ciphertext with value `v`.
    pub fn create_value<T: DecomposableInto<u64>>(&self, v: T) -> RadixCiphertext {
        self.k
            .create_trivial_radix::<T, RadixCiphertext>(v, self.num_blocks)
    }
}

impl Key for ServerKey {
    fn max_int(&self) -> usize {
        self.msg_mod.pow(self.num_blocks as u32) - 1
    }
}
