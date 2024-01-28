//! Functionality for string comparison.

use std::cmp;

use rayon::{join, prelude::*};
use tfhe::integer::{BooleanBlock, IntegerCiphertext, RadixCiphertext};

use crate::server_key::ServerKey;

use super::{logic::all, FheString};

impl FheString {
    /// Returns whether `self` is empty. The result is an encryption of 1 if
    /// this is the case and an encryption of 0 otherwise.
    pub fn is_empty(&self, k: &ServerKey) -> BooleanBlock {
        let term = k.create_value(Self::TERMINATOR);
        k.k.eq_parallelized(&self.0[0].0, &term)
    }

    /// Returns `self == s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn eq(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        // Compare overlapping part.
        let l = cmp::min(self.max_len(), s.max_len());
        let a = self.substr_clear(k, 0, l);
        let b = s.substr_clear(k, 0, l);

        let (overlap_eq, overhang_empty) = join(
            || {
                // Convert strings to radix integers and rely on optimized comparison.
                let radix_a = a.to_long_radix();
                let radix_b = b.to_long_radix();
                k.k.eq_parallelized(&radix_a, &radix_b)
            },
            || {
                // Ensure that overhang is empty.
                match self.max_len().cmp(&s.max_len()) {
                    cmp::Ordering::Greater => self.substr_clear(k, l, self.max_len()).is_empty(k),
                    cmp::Ordering::Less => s.substr_clear(k, l, s.max_len()).is_empty(k),
                    cmp::Ordering::Equal => k.k.create_trivial_boolean_block(true),
                }
            },
        );

        k.k.boolean_bitand(&overlap_eq, &overhang_empty)
    }

    /// Returns `self != s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn ne(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        let eq = self.eq(k, s);
        k.k.boolean_bitnot(&eq)
    }

    /// Returns `self <= s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn le(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        let s_lt_self = s.lt(k, self);
        k.k.boolean_bitnot(&s_lt_self)
    }

    /// Returns `self < s`. The result is an encryption of 1 if this is the case
    /// and an encryption of 0 otherwise.
    pub fn lt(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
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

        let mut is_lt = k.k.create_trivial_boolean_block(false);
        let mut is_eq = k.k.create_trivial_boolean_block(true);

        // is_lt = is_lt || ai < bi
        a_lt_b.iter().zip(&a_eq_b).for_each(|(ai_lt_bi, ai_eq_bi)| {
            // is_lt = is_lt || ai < bi && is_eq
            let ai_lt_bi_and_eq = k.k.boolean_bitand(ai_lt_bi, &is_eq);
            is_lt = k.k.boolean_bitor(&is_lt, &ai_lt_bi_and_eq);

            // is_eq = is_eq && ai == bi
            is_eq = k.k.boolean_bitand(&is_eq, ai_eq_bi);
        });
        is_lt
    }

    /// Returns `self >= s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn ge(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        s.le(k, self)
    }

    /// Returns `self > s`. The result is an encryption of 1 if this is the
    /// case and an encryption of 0 otherwise.
    pub fn gt(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        s.lt(k, self)
    }

    /// Returns whether `self` and `s` are equal when ignoring case.
    pub fn eq_ignore_ascii_case(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        let (self_lower, s_lower) = join(|| self.to_lowercase(k), || s.to_lowercase(k));
        self_lower.eq(k, &s_lower)
    }

    /// Returns whether `self[i..i+s.len]` and `s` are equal.
    pub fn substr_eq(&self, k: &ServerKey, i: usize, s: &FheString) -> BooleanBlock {
        // Extract substring.
        let a = self.substr_clear(k, i, self.max_len());
        let b = s;

        let (mut v, overhang_empty) = join(
            || {
                // v[i] = a[i] == b[i] && b[i] != 0
                a.0.par_iter()
                    .zip(&b.0)
                    .map(|(ai, bi)| {
                        let eq = k.k.eq_parallelized(&ai.0, &bi.0);
                        let is_term = k.k.scalar_eq_parallelized(&bi.0, Self::TERMINATOR);
                        k.k.boolean_bitor(&eq, &is_term)
                    })
                    .collect::<Vec<_>>()
            },
            || {
                // If a is potentially shorter than b, ensure that overhang is empty.
                match a.max_len() < b.max_len() {
                    true => Some(b.substr_clear(k, a.max_len(), b.max_len()).is_empty(k)),
                    false => None,
                }
            },
        );

        if let Some(overhang_empty) = overhang_empty {
            v.push(overhang_empty);
        }

        // Check if all v[i] == 1.
        all(k, &v)
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
