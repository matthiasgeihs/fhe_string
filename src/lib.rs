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

pub use ciphertext::{split::FheStringSliceVector, FheAsciiChar, FheOption, FheString, FheUsize};
pub use client_key::ClientKey;
pub use server_key::ServerKey;

mod ciphertext;
mod client_key;
mod server_key;

/// Generates a fresh key pair using the default parameters. The maximum string
/// length is set to 255.
pub fn generate_keys() -> (ClientKey, ServerKey) {
    generate_keys_with_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 255)
}

/// Generates a fresh key pair using encryption scheme parameters `p` and
/// maximum string length `l`.
pub fn generate_keys_with_params(p: ClassicPBSParameters, l: usize) -> (ClientKey, ServerKey) {
    let ceil_ilog = |a: usize, b: usize| -> usize {
        let l = a.ilog(b);
        match a == b.pow(l) {
            true => l as usize,
            false => (l + 1) as usize,
        }
    };

    let msg_mod = p.message_modulus.0;
    const NUM_ASCII_CHARS: usize = 128;
    let num_blocks_char = ceil_ilog(NUM_ASCII_CHARS, msg_mod);
    let num_blocks_usize = ceil_ilog(l + 1, msg_mod);

    let (client_key, server_key) = gen_keys_radix(p, num_blocks_char);
    (
        ClientKey {
            k: client_key,
            num_blocks_usize,
        },
        ServerKey {
            k: server_key,
            msg_mod,
            num_blocks_char,
            num_blocks_usize,
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
