use std::{any::Any, fmt::Debug, ops::Add, time::Instant};

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

    let test_cases: Vec<TestCase> = vec![
        // search
        TestCase {
            name: |input, pattern| format!("\"{input}\".contains(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.contains(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.contains(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".starts_with(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.starts_with(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.starts_with(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".ends_with(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.ends_with(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.ends_with(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".find(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.find(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.find(sk, pattern);
                Box::new(decrypt_option_int(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".rfind(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.rfind(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.rfind(sk, pattern);
                Box::new(decrypt_option_int(ck, &r))
            },
        },
        // compare
        TestCase {
            name: |input, pattern| format!("\"{input}\".eq(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.eq(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.eq(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".le(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.le(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.le(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".ge(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.ge(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.ge(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".ne(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.ne(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.ne(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".eq_ignore_ascii_case(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.eq_ignore_ascii_case(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.eq_ignore_ascii_case(sk, pattern);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        TestCase {
            name: |input, _pattern| format!("\"{input}\".is_empty()"),
            std: |input, _pattern| Box::new(input.is_empty()),
            fhe: |input, _pattern, sk, ck| {
                let r = input.is_empty(sk);
                Box::new(decrypt_bool(ck, &r))
            },
        },
        // insert
        TestCase {
            name: |input, pattern| format!("\"{input}\".add(\"{pattern}\")"),
            std: |input, pattern| Box::new(input.to_owned().add(pattern)),
            fhe: |input, pattern, sk, ck| {
                let r = input.add(sk, pattern);
                Box::new(r.decrypt(&ck))
            },
        },
        TestCase {
            name: |input, pattern| format!("\"{input}\".repeat(\"{n}\")"),
            std: |input, pattern| Box::new(input.repeat(n)),
            fhe: |input, pattern, sk, ck| {
                let r = input.repeat(sk, n, l);
                Box::new(r.decrypt(&ck))
            },
        },
    ];

    test_cases.iter().for_each(|t| {
        let start = Instant::now();
        let result_std = (t.std)(&input, &pattern);
        let duration_std = start.elapsed();

        let start = Instant::now();
        let result_fhe = (t.fhe)(&input_enc, &pattern_enc, &sk, &ck);
        let duration_fhe = start.elapsed();

        println!("\n{}", (t.name)(&input, &pattern));
        println!("Std: {:?} ({:?})", result_std, duration_std);
        println!("Fhe: {:?} ({:?})", result_fhe, duration_fhe);
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

trait TestCaseOutput: Debug {
    fn as_any(&self) -> &dyn Any;
    fn eq(&self, _: &dyn TestCaseOutput) -> bool;
}

impl<S: 'static + PartialEq + Debug> TestCaseOutput for S {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn eq(&self, other: &dyn TestCaseOutput) -> bool {
        // Do a type-safe casting. If the types are different,
        // return false, otherwise test the values for equality.
        other
            .as_any()
            .downcast_ref::<S>()
            .map_or(false, |a| self == a)
    }
}

impl PartialEq for dyn TestCaseOutput {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

struct TestCase {
    name: fn(input: &str, pattern: &str) -> String,
    std: fn(input: &str, pattern: &str) -> Box<dyn TestCaseOutput>,
    fhe: fn(
        input: &FheString,
        pattern: &FheString,
        server_key: &ServerKey,
        client_key: &ClientKey,
    ) -> Box<dyn TestCaseOutput>,
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
