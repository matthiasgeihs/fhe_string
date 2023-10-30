use crate::ciphertext::tests::{decrypt_bool, encrypt_string, setup};

#[test]
fn is_empty() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "a",
            pad: None,
        },
        TestCase {
            input: "a",
            pad: Some(3),
        },
        TestCase {
            input: "abc",
            pad: None,
        },
        TestCase {
            input: "abc",
            pad: Some(5),
        },
        TestCase {
            input: "",
            pad: None,
        },
        TestCase {
            input: "",
            pad: Some(3),
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let result = t.input.is_empty();

        let result_enc = input_enc.is_empty(&server_key);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    })
}

#[test]
fn eq_ne() {
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
            b: "abc",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: Some(3),
            b: "abc",
            b_pad: Some(5),
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "abcd",
            b_pad: None,
        },
        TestCase {
            a: "abcd",
            a_pad: None,
            b: "ab",
            b_pad: None,
        },
        TestCase {
            a: "a",
            a_pad: None,
            b: "b",
            b_pad: None,
        },
        TestCase {
            a: "a",
            a_pad: None,
            b: "",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        // eq

        let result = t.a.eq(t.b);

        let result_enc = a_enc.eq(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("eq: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // ne

        let result = t.a.ne(t.b);

        let result_enc = a_enc.ne(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("ne: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    })
}

#[test]
fn le_lt_ge_gt() {
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
            b: "abc",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: Some(3),
            b: "abc",
            b_pad: Some(5),
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "abcd",
            b_pad: None,
        },
        TestCase {
            a: "abcd",
            a_pad: None,
            b: "ab",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "bcd",
            b_pad: None,
        },
        TestCase {
            a: "cde",
            a_pad: None,
            b: "abc",
            b_pad: None,
        },
        TestCase {
            a: "a",
            a_pad: None,
            b: "",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        // le

        let result = t.a.le(t.b);

        let result_enc = a_enc.le(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("le: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // lt

        let result = t.a.lt(t.b);

        let result_enc = a_enc.lt(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("lt: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // ge

        let result = t.a.ge(t.b);

        let result_enc = a_enc.ge(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("ge: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // gt

        let result = t.a.gt(t.b);

        let result_enc = a_enc.gt(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("gt: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    })
}

#[test]
fn eq_ignore_case() {
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
            b: "ABC",
            b_pad: None,
        },
        TestCase {
            a: "AbC",
            a_pad: Some(3),
            b: "aBc",
            b_pad: Some(5),
        },
        TestCase {
            a: "ABC",
            a_pad: None,
            b: "def",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        let result = t.a.eq_ignore_ascii_case(t.b);

        let result_enc = a_enc.eq_ignore_ascii_case(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}
