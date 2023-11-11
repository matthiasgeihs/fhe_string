use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::{integer::gen_keys_radix, shortint::ClassicPBSParameters};

pub mod ciphertext;
pub mod client_key;
pub mod error;
pub mod server_key;

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
