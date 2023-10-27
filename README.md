# fhe_string

Library for computing on encrypted strings using [tfhe-rs](https://github.com/zama-ai/tfhe-rs).

## Test

```
TEST_NAME=[insert test name]
RUST_LOG=debug RUST_BACKTRACE=1 cargo test --release $TEST_NAME -- --nocapture
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
