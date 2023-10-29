use tfhe::{integer::RadixCiphertext, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

use crate::{client_key::ClientKey, generate_keys, server_key::ServerKey};

use super::FheString;

mod comparison;

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

fn int_to_bool(x: u64) -> bool {
    match x {
        0 => false,
        1 => true,
        _ => panic!("expected 0 or 1, got {}", x),
    }
}
