# fhe_string

Library for computing on encrypted strings using [tfhe-rs](https://github.com/zama-ai/tfhe-rs).

## Test

```bash
# all tests
cargo test --release

# single test with log
RUST_LOG=debug RUST_BACKTRACE=1 cargo test --release "tests::$TEST_NAME" -- --nocapture --exact
```

## Design principles

- Simplicity over performance

## TODO

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
- ensure that no constructed `FheStringSliceVector` is longer than
  Key::max_int because otherwise we can't ensure correct indexing
