use std::cmp;

use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::server_key::ServerKey;

use super::{
    binary_and,
    logic::{binary_not, binary_or},
    FheAsciiChar, FheString, Uint,
};

impl FheString {
    /// Returns whether `self` is empty. The result is an encryption of 1 if
    /// this is the case and an encryption of 0 otherwise.
    pub fn is_empty(&self, k: &ServerKey) -> RadixCiphertext {
        let zero = k.create_zero();
        k.k.eq_parallelized(&self.0[0].0, &zero)
    }

    /// Returns `self == s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn eq(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        // Pad to same length.
        let l = cmp::max(self.max_len(), s.max_len());
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        // is_eq = is_eq && ai == bi
        let b =
            a.0.par_iter()
                .zip(b.0)
                .map(|(ai, bi)| k.k.eq_parallelized(&ai.0, &bi.0))
                .collect::<Vec<_>>();
        match k.k.unchecked_sum_ciphertexts_vec_parallelized(b) {
            None => k.create_zero(),
            Some(sum) => {
                let len = &k.create_value(a.0.len() as Uint);
                k.k.eq_parallelized(&sum, &len)
            }
        }
    }

    /// Returns `self != s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn ne(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let eq = self.eq(k, s);
        binary_not(k, &eq)
    }

    /// Returns `self <= s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn le(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let s_lt_self = s.lt(k, &self);
        binary_not(k, &s_lt_self)
    }

    /// Returns `self < s`. The result is an encryption of 1 if this is the case
    /// and an encryption of 0 otherwise.
    pub fn lt(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        // Pad to same length.
        let l = cmp::max(self.max_len(), s.max_len());
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        // Evaluate comparison for each character.
        let a_lt_b =
            a.0.par_iter()
                .zip(&b.0)
                .map(|(ai, bi)| k.k.lt_parallelized(&ai.0, &bi.0))
                .collect::<Vec<_>>();
        let a_eq_b =
            a.0.par_iter()
                .zip(&b.0)
                .map(|(ai, bi)| k.k.eq_parallelized(&ai.0, &bi.0))
                .collect::<Vec<_>>();

        let mut is_lt = k.create_zero();
        let mut is_eq = k.create_one();

        // is_lt = is_lt || ai < bi
        a_lt_b.iter().zip(&a_eq_b).for_each(|(ai_lt_bi, ai_eq_bi)| {
            // is_lt = is_lt || ai < bi && is_eq
            let ai_lt_bi_and_eq = binary_and(k, ai_lt_bi, &is_eq);
            is_lt = binary_or(k, &is_lt, &ai_lt_bi_and_eq);

            // is_eq = is_eq && ai == bi
            is_eq = k.k.mul_parallelized(&is_eq, &ai_eq_bi);
        });
        is_lt
    }

    /// Returns `self >= s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn ge(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        s.le(k, &self)
    }

    /// Returns `self > s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn gt(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        s.lt(k, &self)
    }

    /// Returns whether `self` and `s` are equal when ignoring case. The result
    /// is an encryption of 1 if this is the case and an encryption of 0
    /// otherwise.
    pub fn eq_ignore_ascii_case(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        // Pad to same length.
        let l = cmp::max(self.max_len(), s.max_len());
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        let one = k.create_one();
        let mut is_equal = one.clone();

        // is_equal = is_equal && ai.lower == bi.lower
        a.0.iter().zip(b.0).for_each(|(ai, bi)| {
            let ai_lower = ai.to_lowercase(k);
            let bi_lower = bi.to_lowercase(k);
            let ai_eq_bi = k.k.eq_parallelized(&ai_lower.0, &bi_lower.0);
            is_equal = k.k.mul_parallelized(&is_equal, &ai_eq_bi);
        });
        is_equal
    }

    /// Returns whether `self[i..i+s.len]` and `s` are equal. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    ///
    /// # Panics
    /// Panics on index out of bounds.
    pub fn substr_eq(&self, k: &ServerKey, i: usize, s: &FheString) -> RadixCiphertext {
        // Extract substring.
        let a = self.substr_clear(k, i);
        let b = s;

        let mut is_equal = k.create_one();
        let mut b_terminated = k.create_zero();

        a.0.iter().zip(&b.0).for_each(|(ai, bi)| {
            // b_terminated = b_terminated || bi == 0
            let bi_eq_0 = k.k.scalar_eq_parallelized(&bi.0, FheString::TERMINATOR);
            b_terminated = binary_or(k, &b_terminated, &bi_eq_0);

            // is_equal = is_equal && (ai == bi || b_terminated)
            let ai_eq_bi = k.k.eq_parallelized(&ai.0, &bi.0);
            let ai_eq_bi_or_bterm = binary_or(k, &ai_eq_bi, &b_terminated);
            is_equal = k.k.mul_parallelized(&is_equal, &ai_eq_bi_or_bterm);
        });
        binary_and(k, &is_equal, &b_terminated)
    }

    /// Returns `self[i..]`. If `i >= self.len`, returns the empty string.
    fn substr_clear(&self, k: &ServerKey, i: usize) -> FheString {
        let empty_string = Self::empty_string(k);
        let v = self.0.get(i..).unwrap_or(&empty_string.0);
        FheString(v.to_vec())
    }

    fn empty_string(k: &ServerKey) -> Self {
        let term = FheAsciiChar(k.create_value(Self::TERMINATOR));
        FheString(vec![term])
    }
}
