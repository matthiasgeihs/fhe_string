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

    fn setup() -> (ClientKey, ServerKey, FheString, FheString) {
        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = FheString::new(&client_key, &INPUT, INPUT.len()).unwrap();
        let pattern_enc = FheString::new(&client_key, &PATTERN, PATTERN.len()).unwrap();
        (client_key, server_key, input_enc, pattern_enc)
    }

    #[test]
    fn misc() {
        let (client_key, server_key, input_enc, _) = setup();

        // len
        let l = INPUT.len();
        let l_enc = input_enc.len(&server_key);
        let l_dec = client_key.0.decrypt::<u64>(&l_enc);
        println!("len: {} ?= {}", l, l_dec);
        assert_eq!(l, l_dec as usize, "len");
    }

    #[test]
    fn compare() {
        let (client_key, server_key, input_enc, pattern_enc) = setup();

        // is_empty
        let b = INPUT.is_empty() as u8;
        let b_enc = input_enc.is_empty(&server_key);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("is_empty: {} ?= {}", b, b_dec);
        assert_eq!(b, b_dec, "is_empty");

        // eq_ignore_case
        let eq = INPUT.eq_ignore_ascii_case(PATTERN) as u8;
        let eq_enc = input_enc.eq_ignore_case(&server_key, &pattern_enc);
        let eq_dec = client_key.0.decrypt::<u8>(&eq_enc);
        println!("eq_ignore_case: {} ?= {}", eq, eq_dec);
        assert_eq!(eq, eq_dec, "eq_ignore_case");
    }

    #[test]
    fn contains() {
        let (client_key, server_key, input_enc, pattern_enc) = setup();
        // contains
        let b = INPUT.contains(PATTERN) as u8;
        let b_enc = input_enc.contains(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("contains: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "contains");

        // starts_with
        let b = INPUT.starts_with(PATTERN) as u8;
        let b_enc = input_enc.starts_with(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("starts_with: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "starts_with");

        // ends_with
        let b = INPUT.ends_with(PATTERN) as u8;
        let b_enc = input_enc.ends_with(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        println!("ends_with: {} ?= {}", b, b_dec);
        assert_eq!(b as u8, b_dec, "ends_with");
    }

    #[test]
    fn find() {
        let (client_key, server_key, input_enc, pattern_enc) = setup();

        // find
        let opti = INPUT.find(PATTERN);
        let (b, i) = (opti.is_some(), opti.unwrap_or_default());
        let (b_enc, i_enc) = input_enc.find(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        let i_dec = client_key.0.decrypt::<u32>(&i_enc);
        println!("find: ({}, {}) ?= ({}, {})", b as u8, i, b_dec, i_dec);
        assert_eq!((b as u8, i as u32), (b_dec, i_dec), "find");

        // rfind
        let opti = INPUT.rfind(PATTERN);
        let (b, i) = (opti.is_some(), opti.unwrap_or_default());
        let (b_enc, i_enc) = input_enc.rfind(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt::<u8>(&b_enc);
        let i_dec = client_key.0.decrypt::<u32>(&i_enc);
        println!("rfind: ({}, {}) ?= ({}, {})", b as u8, i, b_dec, i_dec);
        assert_eq!((b as u8, i as u32), (b_dec, i_dec), "rfind");
    }

    #[test]
    fn trim() {
        let (client_key, server_key, input_enc, _) = setup();

        // trim
        let t = INPUT.trim();
        let t_enc = input_enc.trim(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim");

        // trim_start
        let t = INPUT.trim_start();
        let t_enc = input_enc.trim_start(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim_start: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim_start");

        // trim_end
        let t = INPUT.trim_end();
        let t_enc = input_enc.trim_end(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("trim_end: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "trim_end");
    }

    #[test]
    fn strip() {
        let (client_key, server_key, input_enc, pattern_enc) = setup();

        // strip_prefix
        let t = INPUT.strip_prefix(PATTERN);
        let t = t.unwrap_or(INPUT);
        let t_enc = input_enc.strip_prefix(&server_key, &pattern_enc);
        let t_dec = t_enc.decrypt(&client_key);
        println!("strip_prefix: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "strip_prefix");

        // strip_suffix
        let t = INPUT.strip_suffix(PATTERN);
        let t = t.unwrap_or(INPUT);
        let t_enc = input_enc.strip_suffix(&server_key, &pattern_enc);
        let t_dec = t_enc.decrypt(&client_key);
        println!("strip_suffix: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "strip_suffix");
    }

    #[test]
    fn case() {
        let (client_key, server_key, input_enc, _) = setup();

        // to_uppercase
        let t = INPUT.to_uppercase();
        let t_enc = input_enc.to_uppercase(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("to_uppercase: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "to_uppercase");

        // to_lowercase
        let t = INPUT.to_lowercase();
        let t_enc = input_enc.to_lowercase(&server_key);
        let t_dec = t_enc.decrypt(&client_key);
        println!("to_lowercase: {} ?= {}", t, t_dec);
        assert_eq!(t, t_dec, "to_lowercase");
    }
}
