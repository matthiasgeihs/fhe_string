use client_key::ClientKey;
use server_key::ServerKey;
use tfhe::{integer::gen_keys_radix, shortint::ClassicPBSParameters};

pub mod ciphertext;
pub mod client_key;
pub mod error;
pub mod server_key;

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

    use crate::{ciphertext::FheString, generate_keys};

    #[test]
    fn all() {
        let input = " defabcabc ";
        let pattern = "abc";

        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = FheString::new(&client_key, &input, input.len()).unwrap();
        let pattern_enc = FheString::new(&client_key, &pattern, pattern.len()).unwrap();

        // is_empty
        let b = input.is_empty() as u8;
        let b_enc = input_enc.is_empty(&server_key);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("is_empty: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "is_empty");

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

        // starts_with
        let b = input.starts_with(pattern) as u8;
        let b_enc = input_enc.starts_with(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("starts_with: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "starts_with");

        // ends_with
        let b = input.ends_with(pattern) as u8;
        let b_enc = input_enc.ends_with(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("ends_with: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "ends_with");

        // find
        let opti = input.find(pattern);
        let (b, i) = (opti.is_some(), opti.unwrap_or_default());
        let (b_enc, i_enc) = input_enc.find(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        let i_dec = client_key.0.decrypt::<u32>(&i_enc);
        println!("find: ({}, {}) ?= ({}, {})", b as u8, i, b_dec, i_dec);
        assert_eq!((b as u8, i as u32), (b_dec, i_dec), "find");

        // rfind
        let opti = input.rfind(pattern);
        let (b, i) = (opti.is_some(), opti.unwrap_or_default());
        let (b_enc, i_enc) = input_enc.rfind(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        let i_dec = client_key.0.decrypt::<u32>(&i_enc);
        println!("rfind: ({}, {}) ?= ({}, {})", b as u8, i, b_dec, i_dec);
        assert_eq!((b as u8, i as u32), (b_dec, i_dec), "rfind");

        // trim
        let t = input.trim();
        let t_enc = input_enc.trim(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim");

        // trim_start
        let t = input.trim_start();
        let t_enc = input_enc.trim_start(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim_start: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim_start");

        // trim_end
        let t = input.trim_end();
        let t_enc = input_enc.trim_end(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim_end: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim_end");
    }
}
