use crate::{
    ciphertext::tests::{encrypt_string, setup},
    FheUsize,
};

#[test]
fn replace() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        replace: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "aa",
            pattern: "a",
            replace: "b",
            pad: None,
        },
        TestCase {
            input: "abdb",
            pattern: "b",
            replace: "c",
            pad: None,
        },
        TestCase {
            input: "aa",
            pattern: "aa",
            replace: "b",
            pad: None,
        },
        TestCase {
            input: "ababcd",
            pattern: "ab",
            replace: "c",
            pad: Some(8),
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
        let replace_enc = encrypt_string(&client_key, t.replace, t.pad);

        let result = t.input.replace(t.pattern, t.replace);

        let result_enc = input_enc.replace(&server_key, &pattern_enc, &replace_enc, result.len());
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = \"{}\"", result);
        println!("fhe = \"{}\"", result_dec);

        assert_eq!(result, result_dec);
    })
}

#[test]
fn replacen() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        replace: &'a str,
        pad: Option<usize>,
        n: usize,
    }

    let test_cases = vec![
        TestCase {
            input: "aaa",
            pattern: "a",
            replace: "b",
            pad: None,
            n: 2,
        },
        TestCase {
            input: "abdb",
            pattern: "b",
            replace: "c",
            pad: Some(4),
            n: 1,
        },
        TestCase {
            input: "aaaa",
            pattern: "aa",
            replace: "b",
            pad: None,
            n: 3,
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
        let replace_enc = encrypt_string(&client_key, t.replace, t.pad);
        let n_enc = FheUsize::new(&client_key, t.n);

        let result = t.input.replacen(t.pattern, t.replace, t.n);

        let result_enc = input_enc.replacen(
            &server_key,
            &pattern_enc,
            &replace_enc,
            &n_enc,
            result.len(),
        );
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = \"{}\"", result);
        println!("fhe = \"{}\"", result_dec);

        assert_eq!(result, result_dec);
    })
}
