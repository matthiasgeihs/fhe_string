//! This module covers the client key that is used for encryption and
//! decryption.

use tfhe::{
    core_crypto::prelude::UnsignedNumeric,
    integer::{
        block_decomposition::{DecomposableInto, RecomposableFrom},
        BooleanBlock, RadixCiphertext, RadixClientKey,
    },
};

/// A key used by the client for string encryption and decryption.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey(pub(crate) RadixClientKey);

impl ClientKey {
    /// Encrypt a single element.
    pub fn encrypt<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
    ) -> RadixCiphertext {
        self.0.encrypt(message)
    }

    /// Decrypt a single element.
    pub fn decrypt<T: RecomposableFrom<u64> + UnsignedNumeric>(&self, ct: &RadixCiphertext) -> T {
        self.0.decrypt(ct)
    }

    /// Decrypt a boolean value.
    pub fn decrypt_bool(&self, ct: &BooleanBlock) -> bool {
        self.0.decrypt_bool(ct)
    }
}

/// A trait for operations common on client key and server key.
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
