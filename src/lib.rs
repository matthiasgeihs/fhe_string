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

    fn setup() -> (ClientKey, ServerKey) {
        let _ = env_logger::try_init(); // Ignore error if already initialized.
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
                input: "axbxc",
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

    #[test]
    fn splitn() {
        let (client_key, server_key) = setup();

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pattern: &'a str,
            pad: Option<usize>,
            n: usize,
        }

        let test_cases = vec![
            TestCase {
                input: "xxx",
                pattern: "x",
                pad: None,
                n: 1,
            },
            TestCase {
                input: "axbxc",
                pattern: "x",
                pad: None,
                n: 2,
            },
            TestCase {
                input: "xxx",
                pattern: "xx",
                pad: None,
                n: 3,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
            let n_enc = encrypt_int(&client_key, t.n as u64);

            let result = t.input.splitn(t.n, t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::splitn(&server_key, &input_enc, &n_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn split_terminator() {
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
                input: "axbxc",
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

            let result = t.input.split_terminator(t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::split_terminator(&server_key, &input_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn split_inclusive() {
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
                input: "axbxc",
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

            let result = t.input.split_inclusive(t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::split_inclusive(&server_key, &input_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn split_ascii_whitespace() {
        let (client_key, server_key) = setup();

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pad: Option<usize>,
        }

        let test_cases = vec![
            TestCase {
                input: " x x x ",
                pad: None,
            },
            TestCase {
                input: "ab cd ed",
                pad: None,
            },
            TestCase {
                input: "ab",
                pad: None,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);

            let result = t.input.split_ascii_whitespace().collect::<Vec<_>>();

            let result_enc = ciphertext::split_ascii_whitespace(&server_key, &input_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn rsplit() {
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
                input: "axbxc",
                pattern: "x",
                pad: None,
            },
            TestCase {
                input: "xxx",
                pattern: "xx",
                pad: None,
            },
            TestCase {
                input: "xaxbx",
                pattern: "x",
                pad: None,
            },
            TestCase {
                input: "axb",
                pattern: "x",
                pad: None,
            },
            TestCase {
                input: "abxxcdxxef",
                pattern: "xx",
                pad: None,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

            let result = t.input.rsplit(t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::rsplit(&server_key, &input_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn rsplit_terminator() {
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
                input: "axbxc",
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

            let result = t.input.rsplit_terminator(t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::rsplit_terminator(&server_key, &input_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn rsplitn() {
        let (client_key, server_key) = setup();

        #[derive(Debug)]
        struct TestCase<'a> {
            input: &'a str,
            pattern: &'a str,
            pad: Option<usize>,
            n: usize,
        }

        let test_cases = vec![
            TestCase {
                input: "xxx",
                pattern: "x",
                pad: None,
                n: 1,
            },
            TestCase {
                input: "axbxc",
                pattern: "x",
                pad: None,
                n: 2,
            },
            TestCase {
                input: "xxx",
                pattern: "xx",
                pad: None,
                n: 3,
            },
        ];

        test_cases.iter().enumerate().for_each(|(i, t)| {
            let input_enc = encrypt_string(&client_key, t.input, t.pad);
            let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
            let n_enc = encrypt_int(&client_key, t.n as u64);

            let result = t.input.rsplitn(t.n, t.pattern).collect::<Vec<_>>();

            let result_enc = ciphertext::rsplitn(&server_key, &input_enc, &n_enc, &pattern_enc);
            let result_dec = result_enc.decrypt(&client_key);

            println!("{:?}", t);
            println!("std = \"{:?}\"", result);
            println!("fhe = \"{:?}\" ", result_dec);

            assert_eq!(result, result_dec, "test case {i}");
        })
    }

    #[test]
    fn split_once() {
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
                input: "axbxc",
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

            let opt_v = t.input.split_once(t.pattern);
            let opt_v = match opt_v {
                Some(v) => Some(vec![v.0.to_string(), v.1.to_string()]),
                None => None,
            };

            let opt_v_enc = ciphertext::split_once(&server_key, &input_enc, &pattern_enc);
            let b_dec = client_key.0.decrypt::<u64>(&opt_v_enc.is_some);
            let v_dec = opt_v_enc.val.decrypt(&client_key);
            let opt_v_dec = match b_dec {
                0 => None,
                _ => Some(v_dec),
            };

            println!("{:?}", t);
            println!("std = \"{:?}\"", opt_v);
            println!("fhe = \"{:?}\" ", opt_v_dec);

            assert_eq!(opt_v, opt_v_dec, "test case {i}");
        })
    }

    #[test]
    fn rsplit_once() {
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
                input: "axbxc",
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

            let opt_v = t.input.rsplit_once(t.pattern);
            let opt_v = match opt_v {
                Some(v) => Some(vec![v.0.to_string(), v.1.to_string()]),
                None => None,
            };

            let opt_v_enc = ciphertext::rsplit_once(&server_key, &input_enc, &pattern_enc);
            let b_dec = client_key.0.decrypt::<u64>(&opt_v_enc.is_some);
            let v_dec = opt_v_enc.val.decrypt(&client_key);
            let opt_v_dec = match b_dec {
                0 => None,
                _ => Some(v_dec),
            };

            println!("{:?}", t);
            println!("std = \"{:?}\"", opt_v);
            println!("fhe = \"{:?}\" ", opt_v_dec);

            assert_eq!(opt_v, opt_v_dec, "test case {i}");
        })
    }
}
