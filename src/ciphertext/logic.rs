use tfhe::integer::RadixCiphertext;

use crate::server_key::ServerKey;

use super::Uint;

// Returns `not a`, assuming `a` is an encryption of a binary value.
pub fn binary_not(k: &ServerKey, a: &RadixCiphertext) -> RadixCiphertext {
    // 1 - a
    let one = k.create_one();
    k.k.sub_parallelized(&one, &a)
}

// Returns `a or b`, assuming `a` and `b` are encryptions of binary values.
pub fn binary_or(k: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    // a + b - a * b
    let a_add_b = k.k.add_parallelized(a, b);
    let a_mul_b = k.k.mul_parallelized(a, b);
    k.k.sub_parallelized(&a_add_b, &a_mul_b)
}

// Returns `a and b`, assuming `a` and `b` are encryptions of binary values.
pub fn binary_and(k: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    // a * b
    k.k.mul_parallelized(a, b)
}

/// Returns 1 if all elements of `v` are equal to 1, or `v.len == 0`. Otherwise
/// returns `0`.
///
/// Expects that all elements of `v` are binary.
pub fn binary_and_vec(k: &ServerKey, v: &[RadixCiphertext]) -> RadixCiphertext {
    let sum = k.k.unchecked_sum_ciphertexts_slice_parallelized(v);
    match sum {
        None => k.create_one(),
        Some(sum) => k.k.scalar_eq_parallelized(&sum, v.len() as Uint),
    }
}

// Returns `a ? b : c`, assuming `a` is an encryption of a binary value.
pub fn binary_if_then_else(
    k: &ServerKey,
    a: &RadixCiphertext,
    b: &RadixCiphertext,
    c: &RadixCiphertext,
) -> RadixCiphertext {
    // a * b + (1 - a) * c
    let a_mul_b = k.k.mul_parallelized(a, b);
    let not_a = binary_not(k, a);
    let not_a_mul_c = k.k.mul_parallelized(&not_a, c);
    k.k.add_parallelized(&a_mul_b, &not_a_mul_c)
}
