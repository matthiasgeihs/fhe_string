use crate::client_key::ClientKey;
use crate::error::Error;
use crate::server_key::ServerKey;
use tfhe::integer::RadixCiphertext;

const TARGET_PRECISION: usize = 8;
const MSG_PRECISION: usize = 2;
const NUM_BLOCKS: usize = TARGET_PRECISION / MSG_PRECISION;

/// FheAsciiChar is a wrapper type for RadixCiphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheAsciiChar(pub(crate) RadixCiphertext);

/// FheString is a wrapper type for Vec<FheAsciiChar>. It is assumed to be
/// 0-terminated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheString(pub(crate) Vec<FheAsciiChar>);

impl FheString {
    pub fn len(&self, k: &ServerKey) -> RadixCiphertext {
        let zero = k.0.create_trivial_zero_radix::<RadixCiphertext>(NUM_BLOCKS);
        let one =
            k.0.create_trivial_radix::<u8, RadixCiphertext>(1, NUM_BLOCKS);

        // a + b - a*b

        let binary_or = |a: &RadixCiphertext, b: &RadixCiphertext| -> RadixCiphertext {
            let a_add_b = k.0.add_parallelized(a, b);
            let a_mul_b = k.0.mul_parallelized(a, b);
            k.0.sub_parallelized(&a_add_b, &a_mul_b)
        };

        let mut l = zero.clone(); // Length.
        let mut b = zero.clone(); // String terminated.

        // l = b * l + (1 - b) * (e == 0) * i
        // b = b || e == 0

        self.0.iter().enumerate().for_each(|(i, e)| {
            println!("len: at index {i}");
            let b_mul_l = k.0.mul_parallelized(&b, &l);

            let e_eq_0 = k.0.scalar_eq_parallelized(&e.0, 0);
            let e_eq_0_mul_i = k.0.scalar_mul_parallelized(&e_eq_0, i as u64);

            let not_b = k.0.sub_parallelized(&one, &b);
            let not_b_mul_e_eq_0_mul_i = k.0.mul_parallelized(&not_b, &e_eq_0_mul_i);

            l = k.0.add_parallelized(&b_mul_l, &not_b_mul_e_eq_0_mul_i);
            b = binary_or(&b, &e_eq_0);
        });

        l
    }
}
