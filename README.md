# fhe_string

`fhe_string` is a library for computing on encrypted strings.

## API primer
The following code snippet demonstrates usage of the API.
```rust
use fhe_string::{ClientKey, ServerKey, generate_keys, StringEncryption};

// Generate keys.
let (client_key, server_key) = generate_keys();

// Define inputs and compute `split` on cleartext.
let (input, sep) = ("a,b,c", ",");
let result_clear = input.split(sep).collect::<Vec<_>>();

// Encrypt inputs (without padding).
let input_enc = input.encrypt(&client_key, None).unwrap();
let sep_enc = sep.encrypt(&client_key, None).unwrap();

// Compute `split` on encrypted string and pattern.
let result_enc = input_enc.split(&server_key, &sep_enc);

// Decrypt and compare result.
let result_dec = result_enc.decrypt(&client_key);
assert_eq!(result_dec, result_clear);
```

## Example `cmd`

The `cmd` example runs a number of string operations on encryptions of the given input string and pattern.
```bash
cargo run --example cmd --release -- --input " A bcbc " --pattern "bc"

# list all options
cargo run --example cmd --release -- --help
```

## Development

In the following we list commands useful during development.

### Linting
```bash
cargo fmt
cargo clippy
```

### Testing and performance evaluation
```bash
# all tests
cargo test --release

# all tests sequentially
cargo test --release -- --test-threads=1

# single test with log
RUST_LOG=trace RUST_BACKTRACE=1 cargo test --release "ciphertext::tests::insert::add" -- --nocapture --exact

# all tests with time measurement (nightly only)
cargo test --release -- --test-threads=1 -Z unstable-options --report-time
```

### Docs generation and running doc tests
```bash
# generate docs
cargo doc --no-deps --open

# run doc tests
cargo test --doc --release -- --show-output
```

## Acknowledgements
This project has been developed for the [Zama Bounty Program](https://github.com/zama-ai/bounty-program), specifically for the bounty ["Create a string library that works on encrypted data using TFHE-rs"](https://github.com/zama-ai/bounty-program/issues/80).

## License

TBD