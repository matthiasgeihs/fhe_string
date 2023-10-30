use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::{integer::gen_keys_radix, shortint::ClassicPBSParameters};

pub mod ciphertext;
pub mod client_key;
pub mod error;
pub mod server_key;

/// Generates a fresh key pair.
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

#[cfg(test)]
mod tests {
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{
        ciphertext::FheString, client_key::ClientKey, generate_keys, server_key::ServerKey,
    };

    const INPUT: &'static str = " defabcabc ";
    const PATTERN: &'static str = "abc";
    // const INPUT: &'static str = "aaaa";
    // const PATTERN: &'static str = "aa";

    fn setup_enc() -> (ClientKey, ServerKey, FheString, FheString) {
        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = FheString::new(&client_key, &INPUT, INPUT.len()).unwrap();
        let pattern_enc = FheString::new(&client_key, &PATTERN, PATTERN.len()).unwrap();
        (client_key, server_key, input_enc, pattern_enc)
    }

    #[test]
    fn misc() {
        let (client_key, server_key, input_enc, _) = setup_enc();

        // len
        let l = INPUT.len();
        let l_enc = input_enc.len(&server_key);
        let l_dec = client_key.0.decrypt::<u64>(&l_enc);
        println!("len: {} ?= {}", l, l_dec);
        assert_eq!(l, l_dec as usize, "len");
    }
}
