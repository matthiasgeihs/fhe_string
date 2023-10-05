use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::{
    integer::gen_keys_radix,
    shortint::{prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS, ClassicPBSParameters},
};

pub mod ciphertext;
pub mod client_key;
pub mod error;
pub mod server_key;

pub fn generate_keys(params: ClassicPBSParameters) -> (ClientKey, ServerKey) {
    let ascii_bitlen = 8;
    let msg_mod = params.message_modulus.0;
    let num_blocks = ascii_bitlen / msg_mod.ilog2() as usize;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    (
        ClientKey(client_key),
        ServerKey {
            k: server_key,
            num_blocks,
            msg_mod,
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::ciphertext::FheString;

    use super::*;

    #[test]
    fn all() {
        let input = "defabc";
        let pattern = "abc";

        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = FheString::new(&client_key, &input, input.len()).unwrap();
        let pattern_enc = FheString::new(&client_key, &pattern, pattern.len()).unwrap();

        // len
        let l = input.len();
        let l_enc = input_enc.len(&server_key);
        let l_dec = client_key.0.decrypt::<u64>(&l_enc);
        println!("len: {} ?= {}", l, l_dec);
        assert_eq!(l, l_dec as usize, "len");

        // contains
        let b = input.contains(pattern) as u8;
        let b_enc = input_enc.contains(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("contains: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "contains");

        // ends_with
        let b = input.ends_with(pattern) as u8;
        let b_enc = input_enc.ends_with(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("ends_with: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "ends_with");

        // is_empty
        let b = input.is_empty() as u8;
        let b_enc = input_enc.is_empty(&server_key);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("is_empty: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "is_empty");
    }
}
