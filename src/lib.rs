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
    let num_blocks = ascii_bitlen / params.message_modulus.0.ilog2() as usize;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);
    (ClientKey(client_key), ServerKey(server_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all() {
        let input = "abc";
        let pattern = "def";

        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = client_key.encrypt(&input, input.len()).unwrap();

        // len
        let l = input.len();
        let l_enc = input_enc.len(&server_key);
        let l_dec = client_key.0.decrypt::<u64>(&l_enc);
        println!("len: {} ?= {}", l, l_dec);
        assert_eq!(l, l_dec as usize, "len");
    }
}
