use std::ops::Add;

use crate::{
    ciphertext::tests::{encrypt_string, setup},
    FheUsize,
};

#[test]
fn add() {
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
            b: "def",
            b_pad: None,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            b: "",
            b_pad: None,
        },
        TestCase {
            a: "",
            a_pad: None,
            b: "def",
            b_pad: None,
        },
        TestCase {
            a: "",
            a_pad: None,
            b: "",
            b_pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let b_enc = encrypt_string(&client_key, t.b, t.b_pad);

        let result = t.a.to_string().add(t.b);

        let result_enc = a_enc.add(&server_key, &b_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}

#[test]
fn repeat() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        a: &'a str,
        a_pad: Option<usize>,
        n: usize,
        l: usize,
    }

    let test_cases = vec![
        TestCase {
            a: "abc",
            a_pad: None,
            n: 0,
            l: 8,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            n: 1,
            l: 8,
        },
        TestCase {
            a: "abc",
            a_pad: None,
            n: 2,
            l: 8,
        },
    ];

    test_cases.iter().for_each(|t| {
        let a_enc = encrypt_string(&client_key, t.a, t.a_pad);
        let n_enc = FheUsize::new(&client_key, t.n);

        let result = t.a.repeat(t.n);

        let result_enc = a_enc.repeat(&server_key, &n_enc, t.l);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec);
    });
}
