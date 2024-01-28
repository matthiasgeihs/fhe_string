use crate::ciphertext::tests::{encrypt_int, encrypt_string, setup};

#[test]
fn split() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "abc",
            pattern: "",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
        TestCase {
            input: "abc",
            pattern: "",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let result = t.input.split(t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.split(&server_key, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn splitn() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
        n: usize,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
            n: 1,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
            n: 2,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
            n: 3,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
            n: 2,
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
        let n_enc = encrypt_int(&client_key, t.n as u64);

        let result = t.input.splitn(t.n, t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.splitn(&server_key, &n_enc, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn split_terminator() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let result = t.input.split_terminator(t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.split_terminator(&server_key, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn split_inclusive() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let result = t.input.split_inclusive(t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.split_inclusive(&server_key, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn split_ascii_whitespace() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: " x x x ",
            pad: None,
        },
        TestCase {
            input: "ab cd ed",
            pad: None,
        },
        TestCase {
            input: "ab",
            pad: None,
        },
        TestCase {
            input: " x x x ",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);

        let result = t.input.split_ascii_whitespace().collect::<Vec<_>>();

        let result_enc = input_enc.split_ascii_whitespace(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn rsplit() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "xaxbx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axb",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "abxxcdxxef",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let result = t.input.rsplit(t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.rsplit(&server_key, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn rsplit_terminator() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let result = t.input.rsplit_terminator(t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.rsplit_terminator(&server_key, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn rsplitn() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
        n: usize,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
            n: 1,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
            n: 2,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
            n: 3,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
            n: 2,
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);
        let n_enc = encrypt_int(&client_key, t.n as u64);

        let result = t.input.rsplitn(t.n, t.pattern).collect::<Vec<_>>();

        let result_enc = input_enc.rsplitn(&server_key, &n_enc, &pattern_enc);
        let result_dec = result_enc.decrypt(&client_key);

        println!("{:?}", t);
        println!("std = {:?}", result);
        println!("fhe = {:?}", result_dec);

        assert_eq!(result, result_dec, "test case {i}");
    })
}

#[test]
fn split_once() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let opt_v = t
            .input
            .split_once(t.pattern)
            .map(|v| (v.0.to_string(), v.1.to_string()));

        let opt_v_enc = input_enc.split_once(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt_bool(&opt_v_enc.is_some);
        let val0_dec = opt_v_enc.val.0.decrypt(&client_key);
        let val1_dec = opt_v_enc.val.1.decrypt(&client_key);
        let opt_v_dec = match b_dec {
            false => None,
            true => Some((val0_dec, val1_dec)),
        };

        println!("{:?}", t);
        println!("std = \"{:?}\"", opt_v);
        println!("fhe = \"{:?}\" ", opt_v_dec);

        assert_eq!(opt_v, opt_v_dec, "test case {i}");
    })
}

#[test]
fn rsplit_once() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pattern: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "xxx",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: None,
        },
        TestCase {
            input: "xxx",
            pattern: "xx",
            pad: None,
        },
        TestCase {
            input: "axbxc",
            pattern: "x",
            pad: Some(8),
        },
    ];

    test_cases.iter().enumerate().for_each(|(i, t)| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);
        let pattern_enc = encrypt_string(&client_key, t.pattern, t.pad);

        let opt_v = t
            .input
            .rsplit_once(t.pattern)
            .map(|v| (v.0.to_string(), v.1.to_string()));

        let opt_v_enc = input_enc.rsplit_once(&server_key, &pattern_enc);
        let b_dec = client_key.0.decrypt_bool(&opt_v_enc.is_some);
        let val0_dec = opt_v_enc.val.0.decrypt(&client_key);
        let val1_dec = opt_v_enc.val.1.decrypt(&client_key);
        let opt_v_dec = match b_dec {
            false => None,
            true => Some((val0_dec, val1_dec)),
        };

        println!("{:?}", t);
        println!("std = \"{:?}\"", opt_v);
        println!("fhe = \"{:?}\" ", opt_v_dec);

        assert_eq!(opt_v, opt_v_dec, "test case {i}");
    })
}
