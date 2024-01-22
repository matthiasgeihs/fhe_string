//! Functionality for string comparison.

use std::cmp;

use rayon::{join, prelude::*};
use tfhe::integer::{IntegerCiphertext, RadixCiphertext};

use crate::server_key::ServerKey;

use super::{
    logic::{binary_and, binary_and_vec, binary_not, binary_or},
    FheString,
};

impl FheString {
    /// Returns whether `self` is empty. The result is an encryption of 1 if
    /// this is the case and an encryption of 0 otherwise.
    pub fn is_empty(&self, k: &ServerKey) -> RadixCiphertext {
        let term = k.create_value(Self::TERMINATOR);
        k.k.eq_parallelized(&self.0[0].0, &term)
    }

    /// Returns `self == s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn eq(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        // Compare overlapping part.
        let l = cmp::min(self.max_len(), s.max_len());
        let a = self.substr_clear(k, 0, l);
        let b = s.substr_clear(k, 0, l);

        let (overlap_eq, overhang_empty) = join(
            || {
                // Convert strings to radix integers and rely on optimized comparison.
                let radix_a = a.to_long_radix();
                let radix_b = b.to_long_radix();
                let eq = k.k.eq_parallelized(&radix_a, &radix_b);

                // Trim exceeding radix blocks to ensure compatibility.
                k.k.trim_radix_blocks_msb(&eq, eq.blocks().len() - k.num_blocks)
            },
            || {
                // Ensure that overhang is empty.
                match self.max_len().cmp(&s.max_len()) {
                    cmp::Ordering::Greater => self.substr_clear(k, l, self.max_len()).is_empty(k),
                    cmp::Ordering::Less => s.substr_clear(k, l, s.max_len()).is_empty(k),
                    cmp::Ordering::Equal => k.create_one(),
                }
            },
        );

        binary_and(k, &overlap_eq, &overhang_empty)
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
        let s_lt_self = s.lt(k, self);
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
        let (a_lt_b, a_eq_b) = join(
            || {
                a.0.par_iter()
                    .zip(&b.0)
                    .map(|(ai, bi)| k.k.lt_parallelized(&ai.0, &bi.0))
                    .collect::<Vec<_>>()
            },
            || {
                a.0.par_iter()
                    .zip(&b.0)
                    .map(|(ai, bi)| k.k.eq_parallelized(&ai.0, &bi.0))
                    .collect::<Vec<_>>()
            },
        );

        let mut is_lt = k.create_zero();
        let mut is_eq = k.create_one();

        // is_lt = is_lt || ai < bi
        a_lt_b.iter().zip(&a_eq_b).for_each(|(ai_lt_bi, ai_eq_bi)| {
            // is_lt = is_lt || ai < bi && is_eq
            let ai_lt_bi_and_eq = binary_and(k, ai_lt_bi, &is_eq);
            is_lt = binary_or(k, &is_lt, &ai_lt_bi_and_eq);

            // is_eq = is_eq && ai == bi
            is_eq = binary_and(k, &is_eq, ai_eq_bi);
        });
        is_lt
    }

    /// Returns `self >= s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn ge(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        s.le(k, self)
    }

    /// Returns `self > s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn gt(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        s.lt(k, self)
    }

    /// Returns whether `self` and `s` are equal when ignoring case. The result
    /// is an encryption of 1 if this is the case and an encryption of 0
    /// otherwise.
    pub fn eq_ignore_ascii_case(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        // Pad to same length.
        let l = cmp::max(self.max_len(), s.max_len());
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        let v: Vec<_> =
            a.0.par_iter()
                .zip(&b.0)
                .map(|(ai, bi)| {
                    let ai_low = ai.to_lowercase(k);
                    let bi_low = bi.to_lowercase(k);
                    k.k.eq_parallelized(&ai_low.0, &bi_low.0)
                })
                .collect();

        binary_and_vec(k, &v)
    }

    /// Returns whether `self[i..i+s.len]` and `s` are equal. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn substr_eq(&self, k: &ServerKey, i: usize, s: &FheString) -> RadixCiphertext {
        // Extract substring.
        let b = s;
        let b_len = b.len(k);
        let a = self.substr_clear(k, i, self.max_len());
        let a = a.truncate(k, &b_len);
        a.eq(k, b)
    }

    /// Returns `self[i..]`. If `i >= self.len`, returns the empty string.
    fn substr_clear(&self, k: &ServerKey, i: usize) -> FheString {
        let empty_string = Self::empty_string(k);
        let v = self.0.get(i..).unwrap_or(&empty_string.0);
        FheString(v.to_vec())
    }

    /// Returns `self[start..end]`. If `start >= self.len`, returns the empty
    /// string. If `end > self.max_len`, set `end = self.max_len`.
    fn substr_clear(&self, k: &ServerKey, start: usize, end: usize) -> FheString {
        let end = cmp::min(self.max_len(), end);
        let mut v = self.0.get(start..end).unwrap_or_default().to_vec();
        v.push(FheString::term_char(k));
        FheString(v.to_vec())
    }

    // Converts the string into a long radix by concatenating its blocks.
    fn to_long_radix(&self) -> RadixCiphertext {
        let blocks: Vec<_> = self
            .0
            .iter()
            .flat_map(|c| c.0.blocks().to_owned())
            .collect();
        RadixCiphertext::from_blocks(blocks)
    }
}
