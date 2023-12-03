//! This library provides functionality for operating on encrypted strings.
//!
//! # Example
//!
//! ```
//! use fhe_string::{ClientKey, ServerKey, generate_keys, StringEncryption};
//!
//! // Generate keys.
//! let (client_key, server_key) = generate_keys();
//!
//! // Define inputs and compute `split` on cleartext.
//! let (input, sep) = ("a,b,c", ",");
//! let result_clear = input.split(sep).collect::<Vec<_>>();
//!
//! // Encrypt inputs (without padding).
//! let input_enc = input.encrypt(&client_key, None).unwrap();
//! let sep_enc = sep.encrypt(&client_key, None).unwrap();
//!
//! // Compute `split` on encrypted string and pattern.
//! let result_enc = input_enc.split(&server_key, &sep_enc);
//!
//! // Decrypt and compare result.
//! let result_dec = result_enc.decrypt(&client_key);
//! assert_eq!(result_dec, result_clear);
//! ```

use std::error::Error;

use tfhe::{
    integer::gen_keys_radix,
    shortint::{parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS, ClassicPBSParameters},
};

pub use ciphertext::{split::FheStringSliceVector, FheAsciiChar, FheOption, FheString};
pub use client_key::ClientKey;
pub use server_key::ServerKey;

mod ciphertext;
mod client_key;
mod server_key;

/// Generates a fresh key pair for handling encrypted strings up to length
/// `2^8-1`.
pub fn generate_keys() -> (ClientKey, ServerKey) {
    generate_keys_with_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
}

/// Generates a fresh key pair for handling encrypted strings up to length
/// `2^8-1`, using the given encryption scheme parameters.
pub fn generate_keys_with_params(params: ClassicPBSParameters) -> (ClientKey, ServerKey) {
    let ascii_bitlen = 8;
    let msg_mod = params.message_modulus.0;
    let num_blocks = ascii_bitlen / msg_mod.ilog2() as usize;
    let (client_key, server_key) = gen_keys_radix(params, num_blocks);
    (
        ClientKey(client_key),
        ServerKey {
            k: server_key,
            num_blocks,
            msg_mod,
        },
    )
}

/// Support for string encryption.
pub trait StringEncryption {
    /// Encrypt `self` into an `FheString`.
    fn encrypt(&self, k: &ClientKey, l: Option<usize>) -> Result<FheString, Box<dyn Error>>;
}

impl StringEncryption for str {
    fn encrypt(&self, k: &ClientKey, l: Option<usize>) -> Result<FheString, Box<dyn Error>> {
        FheString::new(k, self, l)
    }
}
