//! This library provides functionality for operating on encrypted strings.
//!
//! # Example
//!
//! ```
//! use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
//! use fhe_string::{ClientKey, ServerKey, generate_keys, EncryptString};
//!
//! let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
//!
//! let (input, sep) = ("a,b,c", ",");
//! let input_enc = input.encrypt(&client_key, Some(8)).unwrap(); // Pad to length 8.
//! let sep_enc = sep.encrypt(&client_key, None).unwrap(); // No length padding.
//!
//! let result_enc = input_enc.split(&server_key, &sep_enc);
//!
//! assert_eq!(input.split(sep).collect::<Vec<_>>(), result_enc.decrypt(&client_key));
//! ```

use std::error::Error;

use tfhe::{integer::gen_keys_radix, shortint::ClassicPBSParameters};

pub use ciphertext::{split::FheStringSliceVector, FheAsciiChar, FheOption, FheString};
pub use client_key::ClientKey;
pub use server_key::ServerKey;

mod ciphertext;
mod client_key;
mod server_key;

/// Generates a fresh key pair for handling encrypted strings up to length
/// `2^8-1`.
pub fn generate_keys(params: ClassicPBSParameters) -> (ClientKey, ServerKey) {
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
