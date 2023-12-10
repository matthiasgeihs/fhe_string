use crate::ciphertext::tests::{decrypt_bool, decrypt_option_int, encrypt_string, setup};

#[test]
fn find_rfind_contains() {
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
            a: "abcabc",
            a_pad: None,
            b: "ab",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: Some(3),
            b: "d",
            b_pad: Some(5),
        },
        TestCase {
            a: "abcdef",
            a_pad: None,
            b: "cde",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        // find
        let result = t.a.find(t.b);

        let result_enc = a_enc.find(&server_key, &b_enc);
        let result_dec = decrypt_option_int(&client_key, &result_enc);

        println!("find: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // rfind
        let result = t.a.rfind(t.b);

        let result_enc = a_enc.rfind(&server_key, &b_enc);
        let result_dec = decrypt_option_int(&client_key, &result_enc);

        println!("rfind: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // contains
        let result = t.a.contains(t.b);

        let result_enc = a_enc.contains(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("contains: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}

#[test]
fn starts_with_ends_with() {
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
            a: "abcabc",
            a_pad: None,
            b: "ab",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: Some(3),
            b: "d",
            b_pad: Some(5),
        },
        TestCase {
            a: "abcdef",
            a_pad: None,
            b: "cde",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        // starts_with
        let result = t.a.starts_with(t.b);

        let result_enc = a_enc.starts_with(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("starts_with: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);

        // ends_with
        let result = t.a.ends_with(t.b);

        let result_enc = a_enc.ends_with(&server_key, &b_enc);
        let result_dec = decrypt_bool(&client_key, &result_enc);

        println!("ends_with: {:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}
