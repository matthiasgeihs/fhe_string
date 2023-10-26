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
    use tfhe::{integer::RadixCiphertext, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{
        ciphertext::{self, FheString},
        client_key::ClientKey,
        generate_keys,
        server_key::ServerKey,
    };

    // const INPUT: &'static str = " defabcabc ";
    // const PATTERN: &'static str = "abc";
    const INPUT: &'static str = "aaaa";
    const PATTERN: &'static str = "aa";

    fn setup_enc() -> (ClientKey, ServerKey, FheString, FheString) {
        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let input_enc = FheString::new(&client_key, &INPUT, INPUT.len()).unwrap();
        let pattern_enc = FheString::new(&client_key, &PATTERN, PATTERN.len()).unwrap();
        (client_key, server_key, input_enc, pattern_enc)
    }

    fn setup() -> (ClientKey, ServerKey) {
        env_logger::init();
        generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS)
    }

    fn encrypt_string(k: &ClientKey, s: &str, l: Option<usize>) -> FheString {
        let l = l.unwrap_or(s.len());
        FheString::new(k, s, l).unwrap()
    }

    fn encrypt_int(k: &ClientKey, n: u64) -> RadixCiphertext {
        k.0.encrypt(n)
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

    #[test]
    fn compare() {
        let (client_key, server_key, input_enc, pattern_enc) = setup_enc();

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

        // eq
        let eq = INPUT.eq(PATTERN) as u8;
        let eq_enc = input_enc.eq(&server_key, &pattern_enc);
        let eq_dec = client_key.0.decrypt::<u8>(&eq_enc);
        println!("eq: {} ?= {}", eq, eq_dec);
        assert_eq!(eq, eq_dec, "eq");

        // ne
        let ne = INPUT.ne(PATTERN) as u8;
        let ne_enc = input_enc.ne(&server_key, &pattern_enc);
        let ne_dec = client_key.0.decrypt::<u8>(&ne_enc);
        println!("ne: {} ?= {}", ne, ne_dec);
        assert_eq!(ne, ne_dec, "ne");

        // le
        let le = INPUT.le(PATTERN) as u8;
        let le_enc = input_enc.le(&server_key, &pattern_enc);
        let le_dec = client_key.0.decrypt::<u8>(&le_enc);
        println!("le: {} ?= {}", le, le_dec);
        assert_eq!(le, le_dec, "le");

        // ge
        let ge = INPUT.ge(PATTERN) as u8;
        let ge_enc = input_enc.ge(&server_key, &pattern_enc);
        let ge_dec = client_key.0.decrypt::<u8>(&ge_enc);
        println!("ge: {} ?= {}", ge, ge_dec);
        assert_eq!(ge, ge_dec, "ge");
    }

    #[test]
    fn contains() {
        let (client_key, server_key, input_enc, pattern_enc) = setup_enc();
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
        let (client_key, server_key, input_enc, pattern_enc) = setup_enc();

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
        let (client_key, server_key, input_enc, _) = setup_enc();

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
        let (client_key, server_key, input_enc, pattern_enc) = setup_enc();

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
        let (client_key, server_key, input_enc, _) = setup_enc();

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

    #[test]
    fn modify() {
        let (client_key, server_key, input_enc, pattern_enc) = setup_enc();

        // append
        let c = INPUT.to_string() + PATTERN;
        let c_enc = input_enc.append(&server_key, &pattern_enc);
        let c_dec = c_enc.decrypt(&client_key);
        println!("append: {} ?= {}", c, c_dec);
        assert_eq!(c, c_dec, "append");

        // repeat
        let n = 3;
        let l = 8;
        let n_enc = client_key.0.encrypt(n as u8);
        let c = INPUT.repeat(n);
        let c_enc = input_enc.repeat(&server_key, &n_enc, l);
        let c_dec = c_enc.decrypt(&client_key);
        println!("repeat: {} ?= {}", c, c_dec);
        assert_eq!(c, c_dec, "repeat");

        // replace
        let repl = "bb";
        let l = 4;
        let repl_enc = FheString::new(&client_key, repl, repl.len()).unwrap();
        let c = INPUT.replace(PATTERN, repl);
        let c = if c.len() > l { c[..l].to_string() } else { c };
        let c_enc = input_enc.replace(&server_key, &pattern_enc, &repl_enc, l);
        let c_dec = c_enc.decrypt(&client_key);
        println!("replace: {} ?= {}", c, c_dec);
        assert_eq!(c, c_dec, "replace");
    }

    #[test]
    fn replace() {
        env_logger::init();
        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pattern: &'a str,
            replace: &'a str,
            pad: Option<usize>,
        }

        let test_cases = vec![
            TestCase {
                input: "aa",
                pattern: "a",
                replace: "b",
                pad: None,
            },
            TestCase {
                input: "abdb",
                pattern: "b",
                replace: "c",
                pad: None,
            },
            TestCase {
                input: "aa",
                pattern: "aa",
                replace: "b",
                pad: None,
            },
            TestCase {
                input: "ababcd",
                pattern: "ab",
                replace: "c",
                pad: Some(8),
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
            let replace_enc = encrypt_string(&client_key, t.replace, t.pad);

            let result = t.input.replace(t.pattern, t.replace);

            // Cap at max length.
            let l = std::cmp::min(result.len(), FheString::max_len_with_key(&server_key));
            let result = result[..l].to_string();

            let result_enc =
                input_enc.replace(&server_key, &pattern_enc, &replace_enc, result.len());
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("str_result    = \"{}\"", result);
            println!("fhestr_result = \"{}\" ", result_dec);

            assert_eq!(result, result_dec, "replace #{}", i);
        })
    }

    #[test]
    fn replacen() {
        env_logger::init();
        let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pattern: &'a str,
            replace: &'a str,
            pad: Option<usize>,
            n: usize,
        }

        let test_cases = vec![
            TestCase {
                input: "aaa",
                pattern: "a",
                replace: "b",
                pad: None,
                n: 2,
            },
            TestCase {
                input: "abdb",
                pattern: "b",
                replace: "c",
                pad: Some(4),
                n: 1,
            },
            TestCase {
                input: "aaaa",
                pattern: "aa",
                replace: "b",
                pad: None,
                n: 3,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
            let replace_enc = encrypt_string(&client_key, t.replace, t.pad);
            let n_enc = encrypt_int(&client_key, t.n as u64);

            let result = t.input.replacen(t.pattern, t.replace, t.n);

            // Cap at max length.
            let l = std::cmp::min(result.len(), FheString::max_len_with_key(&server_key));
            let result = result[..l].to_string();

            let result_enc = input_enc.replacen(
                &server_key,
                &pattern_enc,
                &replace_enc,
                &n_enc,
                result.len(),
            );
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("str_result    = \"{}\"", result);
            println!("fhestr_result = \"{}\" ", result_dec);

            assert_eq!(result, result_dec, "replacen #{}", i);
        })
    }

    #[test]
    fn split() {
        let (client_key, server_key) = setup();

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pattern: &'a str,
            pad: Option<usize>,
        }

        let test_cases = vec![
            TestCase {
                input: "xxx",
                pattern: "x",
                pad: None,
            },
            TestCase {
                input: "axa",
                pattern: "x",
                pad: None,
            },
            TestCase {
                input: "xxx",
                pattern: "xx",
                pad: None,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

            let result = t.input.split(t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::split(&server_key, &input_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }
}
