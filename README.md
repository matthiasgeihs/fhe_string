# fhe_string

`fhe_string` is a library for computing on encrypted strings using [tfhe-rs](https://github.com/zama-ai/tfhe-rs).
It has been developed for the Zama Bounty Program, Season 4, bounty ["Create a string library that works on encrypted data using TFHE-rs"](https://github.com/zama-ai/bounty-program/issues/80).

## Example `cmd`

The `cmd` example runs a number of string operations on encryptions of the given input string and pattern.
```bash
cargo run --example cmd --release -- --input " A bcbc " --pattern "bc"
```

## Development

The following commands can be used for testing and evaluation during development.
```bash
# all tests
cargo test --release

# all tests sequentially
cargo test --release -- --test-threads=1

# single test with log
RUST_LOG=debug RUST_BACKTRACE=1 cargo test --release "tests::$TEST_NAME" -- --nocapture --exact

# all tests with time measurement (nightly only)
cargo test --release -- --test-threads=1 -Z unstable-options --report-time
```

## State of this project

Up to this point, the library is developed under the principle **"everything encrypted first"**. This means that support for operations on encrypted inputs with hidden length is prioritized over support for operations where parts of the input (e.g., the pattern) is not encrypted, or where the strings are encrypted in way that leaks their length.

### Known limitations

- *Cleartext API not implemented:* Due to time constraints, a dedicated cleartext API, where parts of the input are provided in cleartext, has not been implemented. However, these operations can obviously be emulated, albeit at lower performance in some cases, by also encrypting the cleartext inputs and then calling the ciphertext API.

- *Unpadded strings not implemented:* The original bounty description stated that all strings should be 0-padded. Later, this requirement was relaxed (see note in [bounty description](https://github.com/zama-ai/bounty-program/issues/80)) to allow for unpadded strings that are also indentifiable as such without decryption. Due to time constraints and the principle mentioned above, we did not add this feature yet.

- *Function `split` deviates from standard behavior when called with empty pattern*: Running `split` with an empty pattern is a special case. Some languages like `Python` disallow it entirely. `Rust` in this case returns a character-wise representation of the input string. Our implementation currently does not handle the empty pattern as a special case and produces a list of empty characters with length the input string as a result due to the way the algorithm works. See below for an example output comparison.
```
TestCase {
    input: "xxx",
    pattern: "",
    pad: None,
}

std = "["", "x", "x", "x", ""]"
fhe = "["", "", ""]"
```

- *String functions are implemented on `FheString` instead of `ServerKey`:* The bounty description asks for the string functions to be implemented on the server key type. However, we found it to be more intuitive to have the functions on the `FheString` type, as is the case with the regular string functions. (Obviously, this can easily be changed on request.)

- *Code is provided as a standalone library instead of as a `tfhe-rs` example:* The bounty description asks for the code be provided as an example of the `tfhe-rs` codebase. However, we found that compilation times are much longer when developing an example compared to when developing a standalone library. As this was limiting code iteration time, we decided to develop and provide the code in form of a standalone library. (Obviously, this can easily be changed on request.)

### Possible optimizations if unpadded strings are available

The following functions can be sped up if we decide to add support encrypted strings of known length at a later point in time.

- `ends_with`: currently need to go through whole string because we don't know
  length. then only need to compare the respective ends of the two encrypted
  strings.
- `add`, `repeat`: currently this is a quadratic operation because we don't know
  where the boundaries are. if we know the length, we can just append.

## TODO
- Work on any of the known limitations? (e.g., add support for `split` with empty pattern)
