use tfhe::{integer::BooleanBlock, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

use crate::{client_key::ClientKey, generate_keys_with_params, server_key::ServerKey};

use super::FheString;

mod compare;
mod convert;
mod insert;
mod replace;
mod search;
mod split;
mod trim;

fn setup() -> (ClientKey, ServerKey) {
    let _ = env_logger::try_init(); // Ignore error if already initialized.
    generate_keys_with_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS, 255)
}

fn encrypt_string(k: &ClientKey, s: &str, l: Option<usize>) -> FheString {
    FheString::new(k, s, l).unwrap()
}

fn decrypt_bool(k: &ClientKey, b: &BooleanBlock) -> bool {
    k.k.decrypt_bool(b)
}

#[test]
fn zero_term() {
    // `FheString::TERMINATOR` was added after the fact. Previously, the code
    // did just assume that this is zero. Therefore we check this here. Removing
    // this check would require a careful analysis of the code that it does not
    // rely on this equality anymore.
    assert_eq!(FheString::TERMINATOR, 0);
}

#[test]
fn len() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "",
            pad: None,
        },
        TestCase {
            input: "abc",
            pad: None,
        },
        TestCase {
            input: "abc",
            pad: Some(8),
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);

        let result = t.input.len();

        let result_enc = input_enc.len(&server_key);
        let result_dec = client_key.k.decrypt::<u64>(&result_enc.0) as usize;

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    })
}
