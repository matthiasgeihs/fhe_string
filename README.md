# fhe_string

Library for computing on encrypted strings using [tfhe-rs](https://github.com/zama-ai/tfhe-rs).

## Test

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

## Design decisions

- Everything encrypted first.

## TODO

- implement example app

- implement cleartext api

- implement non-zero terminated strings

- ensure that no constructed `FheStringSliceVector` is longer than
  Key::max_int because otherwise we can't ensure correct indexing

- `split`: Support for empty pattern
```
TestCase {
    input: "xxx",
    pattern: "",
    pad: None,
}

std = "["", "x", "x", "x", ""]"
fhe = "["", "", ""]"
```

## Notes

Functions that can be sped up when it is known whether padding is used:
- `ends_with`: currently need to go through whole string because we don't know
  length. then only need to compare the respective ends of the two encrypted
  strings.

