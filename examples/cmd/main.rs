use std::{any::Any, fmt::Debug, ops::Add, time::Instant};

use clap::Parser;
use fhe_string::{generate_keys, ClientKey, FheOption, FheString, ServerKey};
use tfhe::{integer::RadixCiphertext, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

/// Run string operations in the encrypted domain.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input string to run operations on.
    #[arg(long)]
    input: String,

    /// Pattern to be used for pattern-based string operations.
    #[arg(long)]
    pattern: String,

    /// Substituion string to be used for string replacement operations.
    #[arg(long, default_value = "_")]
    substitution: String,

    /// Target string length after padding. If not provided, minimal padding is applied.
    #[arg(long)]
    pad: Option<usize>,

    /// Value used for operations that require parameter `n`.
    #[arg(long, default_value_t = 3)]
    n: usize,
}

fn main() {
    env_logger::init();

    // Setup.

    let args = Args::parse();
    let input = args.input;
    let pattern = args.pattern;
    let substitution = args.substitution;
    let n = args.n;

    println!("Generating keys...");
    let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    println!("Done.");

    println!("Encrypting input...");
    let input_enc = FheString::new(&client_key, &input, args.pad).unwrap();
    println!("Done.");

    println!("Encrypting pattern...");
    let pattern_enc = FheString::new(&client_key, &pattern, args.pad).unwrap();
    println!("Done.");

    println!("Encrypting substitution...");
    let substitution_enc = FheString::new(&client_key, &substitution, args.pad).unwrap();
    println!("Done.");

    println!("Encrypting n...");
    let n_enc = client_key.encrypt(n as u64);
    println!("Done.");

    let args = TestCaseInput {
        client_key,
        server_key,
        input,
        input_enc,
        n,
        n_enc,
        pattern,
        pattern_enc,
        substitution,
        substitution_enc,
    };

    // Run operations on encrypted string.

    let test_cases: Vec<TestCase> = vec![
        // len
        TestCase {
            name: |args| format!("\"{}\".len()", args.input,),
            std: |args| Box::new(args.input.len()),
            fhe: |args| {
                let r = args.input_enc.len(&args.server_key);
                Box::new(args.client_key.decrypt::<u64>(&r) as usize)
            },
        },
        // search
        TestCase {
            name: |args| format!("\"{}\".contains(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.contains(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.contains(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".starts_with(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.starts_with(&args.pattern)),
            fhe: |args| {
                let r = args
                    .input_enc
                    .starts_with(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".ends_with(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.ends_with(&args.pattern)),
            fhe: |args| {
                let r = args
                    .input_enc
                    .ends_with(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".find(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.find(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.find(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key).map(|x| x as usize))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".rfind(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.rfind(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.rfind(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key).map(|x| x as usize))
            },
        },
        // compare
        TestCase {
            name: |args| format!("\"{}\".eq(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(PartialEq::eq(&args.input, &args.pattern)),
            fhe: |args| {
                let r = args.input_enc.eq(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".le(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.le(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.le(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".ge(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.ge(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.ge(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".ne(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.ne(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.ne(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| {
                format!(
                    "\"{}\".eq_ignore_ascii_case(\"{}\")",
                    args.input, args.pattern
                )
            },
            std: |args| Box::new(args.input.eq_ignore_ascii_case(&args.pattern)),
            fhe: |args| {
                let r = args
                    .input_enc
                    .eq_ignore_ascii_case(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".is_empty()", args.input,),
            std: |args| Box::new(args.input.is_empty()),
            fhe: |args| {
                let r = args.input_enc.is_empty(&args.server_key);
                Box::new(decrypt_bool(&args.client_key, &r))
            },
        },
        // insert
        TestCase {
            name: |args| format!("\"{}\".add(\"{}\")", args.input, args.pattern),
            std: |args| Box::new(args.input.clone().add(&args.pattern)),
            fhe: |args| {
                let r = args.input_enc.add(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".repeat({})", args.input, args.n),
            std: |args| Box::new(args.input.repeat(args.n)),
            fhe: |args| {
                let l = args.input.repeat(args.n).len();
                check_len(&args.server_key, l);
                let r = args.input_enc.repeat(&args.server_key, &args.n_enc, l);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        // replace
        TestCase {
            name: |args| {
                format!(
                    "\"{}\".replace(\"{}\", \"{}\")",
                    args.input, args.pattern, args.substitution
                )
            },
            std: |args| Box::new(args.input.replace(&args.pattern, &args.substitution)),
            fhe: |args| {
                let l = args.input.replace(&args.pattern, &args.substitution).len();
                check_len(&args.server_key, l);
                let r = args.input_enc.replace(
                    &args.server_key,
                    &args.pattern_enc,
                    &args.substitution_enc,
                    l,
                );
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| {
                format!(
                    "\"{}\".replacen(\"{}\", \"{}\", {})",
                    args.input, args.pattern, args.substitution, args.n
                )
            },
            std: |args| {
                Box::new(
                    args.input
                        .replacen(&args.pattern, &args.substitution, args.n),
                )
            },
            fhe: |args| {
                let l = args
                    .input
                    .replacen(&args.pattern, &args.substitution, args.n)
                    .len();
                check_len(&args.server_key, l);
                let r = args.input_enc.replacen(
                    &args.server_key,
                    &args.pattern_enc,
                    &args.substitution_enc,
                    &args.n_enc,
                    l,
                );
                Box::new(r.decrypt(&args.client_key))
            },
        },
        // split
        TestCase {
            name: |args| format!("\"{}\".split(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .split(&args.pattern)
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args.input_enc.split(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".rsplit(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .rsplit(&args.pattern)
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args.input_enc.rsplit(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".split_once(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .split_once(&args.pattern)
                        .map(|s| (s.0.to_string(), s.1.to_string())),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .split_once(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_option_string_pair(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".rsplit_once(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .rsplit_once(&args.pattern)
                        .map(|s| (s.0.to_string(), s.1.to_string())),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .rsplit_once(&args.server_key, &args.pattern_enc);
                Box::new(decrypt_option_string_pair(&args.client_key, &r))
            },
        },
        TestCase {
            name: |args| {
                format!(
                    "\"{}\".splitn({}, \"{}\")",
                    args.input, args.n, args.pattern,
                )
            },
            std: |args| {
                Box::new(
                    args.input
                        .splitn(args.n, &args.pattern)
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>(),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .splitn(&args.server_key, &args.n_enc, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| {
                format!(
                    "\"{}\".rsplitn({}, \"{}\")",
                    args.input, args.n, args.pattern,
                )
            },
            std: |args| {
                Box::new(
                    args.input
                        .rsplitn(args.n, &args.pattern)
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>(),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .rsplitn(&args.server_key, &args.n_enc, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".split_terminator(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .split_terminator(&args.pattern)
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .split_terminator(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".rsplit_terminator(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .rsplit_terminator(&args.pattern)
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .rsplit_terminator(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".split_inclusive(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .split_inclusive(&args.pattern)
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .split_inclusive(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".split_ascii_whitespace()", args.input),
            std: |args| {
                Box::new(
                    args.input
                        .split_ascii_whitespace()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>(),
                )
            },
            fhe: |args| {
                let r = args.input_enc.split_ascii_whitespace(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        // trim
        TestCase {
            name: |args| format!("\"{}\".trim()", args.input),
            std: |args| Box::new(args.input.trim().to_string()),
            fhe: |args| {
                let r = args.input_enc.trim(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".trim_start()", args.input),
            std: |args| Box::new(args.input.trim_start().to_string()),
            fhe: |args| {
                let r = args.input_enc.trim_start(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".trim_end()", args.input),
            std: |args| Box::new(args.input.trim_end().to_string()),
            fhe: |args| {
                let r = args.input_enc.trim_end(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".strip_prefix(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .strip_prefix(&args.pattern)
                        .map(|x| x.to_string()),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .strip_prefix(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".strip_suffix(\"{}\")", args.input, args.pattern),
            std: |args| {
                Box::new(
                    args.input
                        .strip_suffix(&args.pattern)
                        .map(|x| x.to_string()),
                )
            },
            fhe: |args| {
                let r = args
                    .input_enc
                    .strip_suffix(&args.server_key, &args.pattern_enc);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        // convert
        TestCase {
            name: |args| format!("\"{}\".to_lowercase()", args.input),
            std: |args| Box::new(args.input.to_lowercase().to_string()),
            fhe: |args| {
                let r = args.input_enc.to_lowercase(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
        TestCase {
            name: |args| format!("\"{}\".to_uppercase()", args.input),
            std: |args| Box::new(args.input.to_uppercase().to_string()),
            fhe: |args| {
                let r = args.input_enc.to_uppercase(&args.server_key);
                Box::new(r.decrypt(&args.client_key))
            },
        },
    ];

    test_cases.iter().for_each(|t| {
        let start = Instant::now();
        let result_std = (t.std)(&args);
        let duration_std = start.elapsed();

        let start = Instant::now();
        let result_fhe = (t.fhe)(&args);
        let duration_fhe = start.elapsed();

        println!("\n{}", (t.name)(&args));
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

struct TestCaseInput {
    input: String,
    pattern: String,
    substitution: String,
    n: usize,
    input_enc: FheString,
    pattern_enc: FheString,
    substitution_enc: FheString,
    n_enc: RadixCiphertext,
    server_key: ServerKey,
    client_key: ClientKey,
}

struct TestCase {
    name: fn(input: &TestCaseInput) -> String,
    std: fn(input: &TestCaseInput) -> Box<dyn TestCaseOutput>,
    fhe: fn(input: &TestCaseInput) -> Box<dyn TestCaseOutput>,
}

fn decrypt_bool(k: &ClientKey, b: &RadixCiphertext) -> bool {
    let x = k.decrypt::<u64>(b);
    int_to_bool(x)
}

fn decrypt_option_string_pair(
    k: &ClientKey,
    opt: &FheOption<(FheString, FheString)>,
) -> Option<(String, String)> {
    let is_some = k.decrypt::<u64>(&opt.is_some);
    match is_some {
        0 => None,
        1 => {
            let val0 = opt.val.0.decrypt(k);
            let val1 = opt.val.1.decrypt(k);
            Some((val0, val1))
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

fn check_len(k: &ServerKey, l: usize) {
    let max_len = FheString::max_len_with_key(k);
    if l > max_len {
        println!("Warning: Length of cleartext result ({l}) exceeds maximum length of encrypted string ({max_len})");
    }
}
