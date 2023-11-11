use std::{fmt::Display, time::Instant};

use clap::Parser;
use fhe_string::{
    ciphertext::{FheOption, FheString},
    client_key::ClientKey,
    generate_keys,
    server_key::ServerKey,
};
use tfhe::{integer::RadixCiphertext, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

/// Run operations on an encrypted string.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input string to encrypt and run operations on.
    #[arg(long)]
    input: String,

    /// Pattern to be used for operations on encrypted input string.
    #[arg(long)]
    pattern: String,

    /// Length encrypted strings are padded to. If `None`, no additional padding
    /// is applied.
    #[arg(long)]
    padlength: Option<usize>,
}

fn main() {
    env_logger::init();

    // Setup.

    let args = Args::parse();
    let input = args.input;
    let pattern = args.pattern;

    println!("Generating keys...");
    let (ck, sk) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    println!("Done.");

    println!("Encrypting input...");
    let input_enc = FheString::new(&ck, &input, args.padlength).unwrap();
    println!("Done.");

    println!("Encrypting pattern...");
    let pattern_enc = FheString::new(&ck, &pattern, args.padlength).unwrap();
    println!("Done.");

    // Run operations on encrypted string.

    struct TestCase<T> {
        name: fn(input: &str, patter: &str) -> String,
        std: fn(input: &str, patter: &str) -> T,
        fhe: fn(
            input: &FheString,
            pattern: &FheString,
            server_key: &ServerKey,
            client_key: &ClientKey,
        ) -> T,
    }

    let test_cases = vec![
        TestCase {
            name: |input, pattern| format!("\"{input}\".contains(\"{pattern}\")"),
            std: |input, pattern| input.contains(pattern),
            fhe: |input, pattern, sk, ck| {
                let r = input.contains(sk, pattern);
                decrypt_bool(ck, &r)
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".starts_with(\"{pattern}\")"),
            std: |input, pattern| input.starts_with(pattern),
            fhe: |input, pattern, sk, ck| {
                let r = input.starts_with(sk, pattern);
                decrypt_bool(ck, &r)
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".ends_with(\"{pattern}\")"),
            std: |input, pattern| input.ends_with(pattern),
            fhe: |input, pattern, sk, ck| {
                let r = input.ends_with(sk, pattern);
                decrypt_bool(ck, &r)
            },
        },
        // TestCase {
        //     name: |input, pattern| format!("\"{input}\".find(\"{pattern}\")"),
        //     std: |input, pattern| input.find(pattern),
        //     fhe: |input, pattern, sk, ck| {
        //         let r = input.find(sk, pattern);
        //         decrypt_option_int(ck, &r)
        //     },
        // },
    ];

    test_cases.iter().for_each(|t| {
        let start = Instant::now();
        let result_std = (t.std)(&input, &pattern);
        let duration_std = start.elapsed();

        let start = Instant::now();
        let result_fhe = (t.fhe)(&input_enc, &pattern_enc, &sk, &ck);
        let duration_fhe = start.elapsed();

        println!("\n{}", (t.name)(&input, &pattern));
        println!("Std: {result_std} ({:?})", duration_std);
        println!("Fhe: {result_fhe} ({:?})", duration_fhe);
        println!(
            "Equal: {}",
            if result_std == result_fhe {
                "✅"
            } else {
                "❌"
            }
        )
    });
}

fn decrypt_bool(k: &ClientKey, b: &RadixCiphertext) -> bool {
    let x = k.decrypt::<u64>(&b);
    int_to_bool(x)
}

fn decrypt_option_int(k: &ClientKey, opt: &FheOption<RadixCiphertext>) -> Option<usize> {
    let is_some = k.decrypt::<u64>(&opt.is_some);
    match is_some {
        0 => None,
        1 => {
            let val = k.decrypt::<u64>(&opt.val);
            Some(val as usize)
        }
        _ => panic!("expected 0 or 1, got {}", is_some),
    }
}

fn int_to_bool(x: u64) -> bool {
    match x {
        0 => false,
        1 => true,
        _ => panic!("expected 0 or 1, got {}", x),
    }
}
