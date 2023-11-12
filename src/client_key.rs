use tfhe::{
    core_crypto::prelude::UnsignedNumeric,
    integer::{
        block_decomposition::{DecomposableInto, RecomposableFrom},
        RadixCiphertext, RadixClientKey,
    },
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey(pub(crate) RadixClientKey);

impl ClientKey {
    pub fn encrypt<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
    ) -> RadixCiphertext {
        self.0.encrypt(message)
    }

    pub fn decrypt<T: RecomposableFrom<u64> + UnsignedNumeric>(&self, ct: &RadixCiphertext) -> T {
        self.0.decrypt(ct)
    }
}

pub trait Key {
    /// Returns the maximum value that can be stored in a ciphertext.
    fn max_int(&self) -> usize;
}

impl Key for ClientKey {
    fn max_int(&self) -> usize {
        let msg_mod = self.0.parameters().message_modulus().0;
        let blocks = self.0.num_blocks();
        msg_mod.pow(blocks as u32) - 1
    }
}
