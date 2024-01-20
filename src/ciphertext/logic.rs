//! Functionality for logical operations.

use tfhe::integer::RadixCiphertext;

use crate::server_key::ServerKey;

use super::Uint;

// Returns `not a`, assuming `a` is an encryption of a binary value.
pub fn binary_not(k: &ServerKey, a: &RadixCiphertext) -> RadixCiphertext {
    k.k.scalar_bitxor_parallelized(a, 1)
}

// Returns `a or b`, assuming `a` and `b` are encryptions of binary values.
pub fn binary_or(k: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    k.k.bitor_parallelized(a, b)
}

// Returns `a and b`, assuming `a` and `b` are encryptions of binary values.
pub fn binary_and(k: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    k.k.bitand_parallelized(a, b)
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

/// Returns 1 if an element of `v` is equal to 1. Otherwise returns `0`.
///
/// Expects that all elements of `v` are binary.
pub fn binary_or_vec(k: &ServerKey, v: &[RadixCiphertext]) -> RadixCiphertext {
    let sum = k.k.unchecked_sum_ciphertexts_slice_parallelized(v);
    match sum {
        None => k.create_zero(),
        Some(sum) => k.k.scalar_gt_parallelized(&sum, 0 as Uint),
    }
}

// Returns `a ? b : c`, assuming `a` is an encryption of a binary value.
pub fn binary_if_then_else(
    k: &ServerKey,
    a: &RadixCiphertext,
    b: &RadixCiphertext,
    c: &RadixCiphertext,
) -> RadixCiphertext {
    k.k.if_then_else_parallelized(a, b, c)
}
