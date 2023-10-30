use crate::ciphertext::tests::{encrypt_string, setup};

#[test]
fn to_lowercase_to_uppercase() {
    let (client_key, server_key) = setup();

    #[derive(Debug)]
    struct TestCase<'a> {
        input: &'a str,
        pad: Option<usize>,
    }

    let test_cases = vec![
        TestCase {
            input: "ABC",
            pad: None,
        },
        TestCase {
            input: "Abc",
            pad: None,
        },
        TestCase {
            input: "abc def",
            pad: None,
        },
    ];

    test_cases.iter().for_each(|t| {
        let input_enc = encrypt_string(&client_key, t.input, t.pad);

        // to_lowercase
        let result = t.input.to_lowercase();

        let result_enc = input_enc.to_lowercase(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("to_lowercase: {:?}", t);
        println!("std = \"{:?}\"", result);
        println!("fhe = \"{:?}\" ", result_dec);

        assert_eq!(result, result_dec);

        // to_uppercase
        let result = t.input.to_uppercase();

        let result_enc = input_enc.to_uppercase(&server_key);
        let result_dec = result_enc.decrypt(&client_key);

        println!("to_uppercase: {:?}", t);
        println!("std = \"{:?}\"", result);
        println!("fhe = \"{:?}\" ", result_dec);

        assert_eq!(result, result_dec);
    })
}
