//! This module covers the client key that is used for encryption and
//! decryption.

use tfhe::{
    core_crypto::prelude::UnsignedNumeric,
    integer::{
        block_decomposition::{DecomposableInto, RecomposableFrom},
        BooleanBlock, RadixCiphertext, RadixClientKey,
    },
};

use crate::ciphertext::FheUsize;

/// A key used by the client for string encryption and decryption.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey {
    pub(crate) k: RadixClientKey,
    pub(crate) num_blocks_usize: usize,
}

impl ClientKey {
    /// Encrypt a single element.
    pub fn encrypt<T: DecomposableInto<u64> + UnsignedNumeric>(
        &self,
        message: T,
    ) -> RadixCiphertext {
        self.k.encrypt(message)
    }

    /// Decrypt a single element.
    pub fn decrypt<T: RecomposableFrom<u64> + UnsignedNumeric>(&self, ct: &RadixCiphertext) -> T {
        self.k.decrypt(ct)
    }

    /// Decrypt a usize.
    pub fn decrypt_usize(&self, ct: &FheUsize) -> usize {
        self.k.decrypt::<u64>(&ct.0) as usize
    }

    /// Decrypt a boolean value.
    pub fn decrypt_bool(&self, ct: &BooleanBlock) -> bool {
        self.k.decrypt_bool(ct)
    }
}

/// A trait for operations common on client key and server key.
pub trait Key {
    /// Returns the message space modulus.
    fn msg_mod(&self) -> usize;
    /// Returns the number of blocks used to store an encrypted usize.
    fn num_blocks_usize(&self) -> usize;
}

impl Key for ClientKey {
    fn msg_mod(&self) -> usize {
        self.k.parameters().message_modulus().0
    }

    fn num_blocks_usize(&self) -> usize {
        self.num_blocks_usize
    }
}
