//! Functionality for logical operations.

use tfhe::integer::{
    block_decomposition::DecomposableInto, server_key::ScalarMultiplier, BooleanBlock,
    IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext,
};

use crate::server_key::ServerKey;

use super::FheUsize;

// Returns `a ? b : 0`.
pub fn if_then_else_zero<T: IntegerRadixCiphertext>(k: &ServerKey, a: &BooleanBlock, b: &T) -> T {
    let a_radix = a.clone().into_radix(b.blocks().len(), &k.k);
    k.k.mul_parallelized(&a_radix, b)
}

// Returns `a ? b : 0`, where `b` is a scalar.
pub fn scalar_if_then_else_zero<Scalar>(k: &ServerKey, a: &BooleanBlock, b: Scalar) -> FheUsize
where
    Scalar: ScalarMultiplier + DecomposableInto<u8>,
{
    let a_radix = a.clone().into_radix(k.num_blocks_usize, &k.k);
    k.k.scalar_mul_parallelized(&a_radix, b)
}

// Returns `a ? b : c`.
pub fn if_then_else_bool(
    k: &ServerKey,
    a: &BooleanBlock,
    b: &BooleanBlock,
    c: &BooleanBlock,
) -> BooleanBlock {
    let b: RadixCiphertext = b.clone().into_radix(1, &k.k);
    let c: RadixCiphertext = c.clone().into_radix(1, &k.k);
    let d = k.k.if_then_else_parallelized(a, &b, &c);
    BooleanBlock::new_unchecked(d.blocks()[0].clone())
}

// Returns true if any of the elements of `v` is true.
pub fn any(k: &ServerKey, v: &[BooleanBlock]) -> BooleanBlock {
    let v: Vec<RadixCiphertext> = v
        .iter()
        .map(|vi| vi.clone().into_radix(k.num_blocks_usize, &k.k))
        .collect();
    let sum = k.k.unchecked_sum_ciphertexts_vec_parallelized(v);
    match sum {
        None => k.k.create_trivial_boolean_block(false),
        Some(sum) => k.k.scalar_gt_parallelized(&sum, 0u8),
    }
}

// Returns true if all of the elements of `v` are true.
pub fn all(k: &ServerKey, v: &[BooleanBlock]) -> BooleanBlock {
    let v: Vec<RadixCiphertext> = v
        .iter()
        .map(|vi| vi.clone().into_radix(k.num_blocks_usize, &k.k))
        .collect();
    let l = v.len();
    let sum = k.k.unchecked_sum_ciphertexts_vec_parallelized(v);
    match sum {
        None => k.k.create_trivial_boolean_block(true),
        Some(sum) => k.k.scalar_eq_parallelized(&sum, l as u64),
    }
}
