use crate::ciphertext::tests::{decrypt_option_string, encrypt_string, setup};

#[test]
fn trim_trim_start_trim_end() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "   abc   ",
            pad: None,
        },
        TestCase {
            input: "abc   ",
            pad: None,
        },
        TestCase {
            input: "   abc",
            pad: None,
        },
        TestCase {
            input: "abc",
            pad: None,
        },
        TestCase {
            input: "a ",
            pad: Some(3),
        },
        TestCase {
            input: "",
            pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);

        // trim
        let result = t.input.trim();

        let result_enc = input_enc.trim(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("trim: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // trim_start
        let result = t.input.trim_start();

        let result_enc = input_enc.trim_start(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("trim_start: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // trim_end
        let result = t.input.trim_end();

        let result_enc = input_enc.trim_end(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("trim_end: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    })
}

#[test]
fn strip_prefix_strip_suffix() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        a: &'a str,
        a_pad: Option<usize>,
        b: &'a str,
        b_pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            a: "abc",
            a_pad: None,
            b: "ab",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "bc",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "abc",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "def",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        // strip_prefix
        let result = t.a.strip_prefix(t.b).map(|s| s.to_string());

        let result_enc = a_enc.strip_prefix(&server_key, &b_enc);
        let result_dec = decrypt_option_string(&client_key, &result_enc);

        println!("strip_prefix: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // strip_suffix
        let result = t.a.strip_suffix(t.b).map(|s| s.to_string());

        let result_enc = a_enc.strip_suffix(&server_key, &b_enc);
        let result_dec = decrypt_option_string(&client_key, &result_enc);

        println!("strip_suffix: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}
