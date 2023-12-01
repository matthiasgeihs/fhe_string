# fhe_string

`fhe_string` is a library for computing on encrypted strings using [tfhe-rs](https://github.com/zama-ai/tfhe-rs).


The following example shows how the library is used.
```rust
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use fhe_string::{ClientKey, ServerKey, generate_keys, StringEncryption};

// Generate keys.
let (client_key, server_key) = generate_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

// Encrypt inputs.
let (input, sep) = ("a,b,c", ",");
let input_enc = input.encrypt(&client_key, Some(8)).unwrap(); // Pad to length 8.
let sep_enc = sep.encrypt(&client_key, None).unwrap(); // No length padding.

// Compute string function.
let result_enc = input_enc.split(&server_key, &sep_enc);

// Decrypt and compare result.
let result_dec = result_enc.decrypt(&client_key);
assert_eq!(input.split(sep).collect::<Vec<_>>(), result_dec);
```

## Example `cmd`

The `cmd` example runs a number of string operations on encryptions of the given input string and pattern.
```bash
cargo run --example cmd --release -- --input " A bcbc " --pattern "bc"

# list all options
cargo run --example cmd --release -- --help
```

## Development

The following commands can be used for testing and evaluation.
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

The following commands are for generating docs and running doc tests.
```bash
# generate docs
cargo doc --no-deps --open

# run doc tests
cargo test --doc --release -- --show-output
```

## State of this project

This library is developed under the principle **"everything encrypted first"**. This means that support for operations with encrypted inputs is prioritized over support for operations where parts of the input (e.g., the pattern) is not encrypted, or where the strings are encrypted in a way that leaks their length.

### Known limitations

- *No cleartext API:* Due to time constraints and because of the encryption-first principle mentioned above, a dedicated cleartext API, where parts of the input are provided in cleartext, has not been implemented. However, these operations can obviously be emulated, albeit at lower performance in some cases, by encrypting the cleartext inputs and then calling the ciphertext API.

- *No optimizations for unpadded strings:* The original bounty description stated that all strings should be 0-padded. Later, this requirement was relaxed (see note in [bounty description](https://github.com/zama-ai/bounty-program/issues/80)) to allow for unpadded strings that are indentifiable as such without decryption. Due to time constraints and the principle mentioned above, we did not add this feature yet.

- *String functions are implemented on `FheString` instead of `ServerKey`:* The bounty description asks for the string functions to be implemented on the server key type. However, we found it to be more intuitive to have the functions on the `FheString` type, similar to how regular string functions are available on their string type. (Obviously, this can easily be changed on request.)

- *Code is provided as a standalone library instead of as a `tfhe-rs` example:* The bounty description asks for the code be provided as an example that is part of the `tfhe-rs` codebase. However, we found that compilation times were much longer when compiling the code in form of an example compared compiling it as a standalone library. As this was limiting code iteration time, we decided to develop and provide the code in form of a standalone library. (Obviously, this can easily be changed on request.)

- *Restricted to strings of length < 256:* Currently, the library does not support encrypted strings longer than 255 characters. This is due to the fact that for our `FheString` algorithms to work, we need to be able to represent encrypted integers up to the maximum string length. The size of encrypted integers is fixed at key generation. We could have opted for supporting longer strings (in fact, this is an easy change to the key generation function), but we felt that 256 characters is more than enough initially, considering the limited performance.

### Possible optimizations if unpadded strings are available

Currently, all encrypted strings are padded using encryptions of 0 to hide their length.
In the following, we outline how a number of string functions could be optimized if we decide to add support for unpadded encrypted strings in the future.

- `ends_with`: currently need to go through whole string because we don't know
  length. then only need to compare the respective ends of the two encrypted
  strings.
- `add`, `repeat`: currently this is a quadratic operation because we don't know
  where the boundaries are. if we don't have padding, we can just append.

### TODO
- Remove "TODO" section before submission
- Work on any of the known limitations? (e.g., add support for cleartext pattern, unpadded strings)
- Everywhere, check that values from `k.create_trivial` are not part of output. (This would leak information to third party.)
  - In particular, in `split.rs`, when creating `FheOption.is_some` and `FheOption.start` for string slices, use proper encryption instead of `create_trivial`.
- Use public key for encryption.

## Acknowledgements
This project has been developed for the [Zama Bounty Program](https://github.com/zama-ai/bounty-program), specifically for the bounty ["Create a string library that works on encrypted data using TFHE-rs"](https://github.com/zama-ai/bounty-program/issues/80).
