use std::fmt::Debug;

use tfhe::integer::{RadixCiphertext, ServerKey as IntegerServerKey};

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
    pub fn create_zero(&self) -> RadixCiphertext {
        self.k
            .create_trivial_zero_radix::<RadixCiphertext>(self.num_blocks)
    }

    pub fn create_one(&self) -> RadixCiphertext {
        self.k
            .create_trivial_radix::<u8, RadixCiphertext>(1, self.num_blocks)
    }

    pub fn max_int(&self) -> usize {
        self.msg_mod.pow(self.num_blocks as u32) - 1
    }
}
