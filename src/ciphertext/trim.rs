//! Functionality for string trimming.

use rayon::{join, prelude::*};
use tfhe::integer::BooleanBlock;

use crate::server_key::ServerKey;

use super::{
    index_of_unchecked, logic::if_then_else_zero, rindex_of_unchecked, FheAsciiChar, FheOption,
    FheString, FheUsize,
};

impl FheAsciiChar {
    /// Returns whether this is a whitespace character.
    pub fn is_whitespace(&self, k: &ServerKey) -> BooleanBlock {
        // Whitespace characters: 9 (Horizontal tab), 10 (Line feed), 11
        // (Vertical tab), 12 (Form feed), 13 (Carriage return), 32 (Space)

        // (9 <= c <= 13) || c == 32
        let c_geq_9 = k.k.scalar_ge_parallelized(&self.0, 9u8);
        let c_leq_13 = k.k.scalar_le_parallelized(&self.0, 13u8);
        let c_geq_9_and_c_leq_13 = k.k.boolean_bitand(&c_geq_9, &c_leq_13);
        let c_eq_32 = k.k.scalar_eq_parallelized(&self.0, 32u8);
        k.k.boolean_bitor(&c_geq_9_and_c_leq_13, &c_eq_32)
    }
}

impl FheString {
    /// Returns `self[i..]` where `i` is the index of the first non-whitespace
    /// character.
    pub fn trim_start(&self, k: &ServerKey) -> FheString {
        let i_opt = self.find_pred_unchecked(k, |k, c| {
            let is_whitespace = c.is_whitespace(k);
            k.k.boolean_bitnot(&is_whitespace)
        });

        let i = if_then_else_zero(k, &i_opt.is_some, &i_opt.val);
        self.substr_from(k, &i)
    }

    /// Returns `self[..i+1]` where `i` is the index of the last non-whitespace
    /// character.
    pub fn trim_end(&self, k: &ServerKey) -> FheString {
        let i_opt = self.rfind_pred_unchecked(k, |k, c| {
            // !is_terminator(c) && !is_whitespace(c)
            let is_term = k.k.scalar_eq_parallelized(&c.0, Self::TERMINATOR);
            let not_term = k.k.boolean_bitnot(&is_term);
            let is_whitespace = c.is_whitespace(k);
            let not_whitespace = k.k.boolean_bitnot(&is_whitespace);
            k.k.boolean_bitand(&not_term, &not_whitespace)
        });

        // i = i_opt.is_some ? i_opt.val + 1 : 0
        let val_add_1 = k.k.scalar_add_parallelized(&i_opt.val, 1);
        let i = if_then_else_zero(k, &i_opt.is_some, &val_add_1);
        self.truncate(k, &i)
    }

    /// Returns `self[i..j+1]` where `i` is the index of the first
    /// non-whitespace character and `j` is the index of the last non-whitespace
    /// character.
    pub fn trim(&self, k: &ServerKey) -> FheString {
        let found = self.find_all_pred_unchecked(k, |k, c| {
            // !is_terminator(c) && !is_whitespace(c)
            let is_term = k.k.scalar_eq_parallelized(&c.0, Self::TERMINATOR);
            let not_term = k.k.boolean_bitnot(&is_term);
            let is_whitespace = c.is_whitespace(k);
            let not_whitespace = k.k.boolean_bitnot(&is_whitespace);
            k.k.boolean_bitand(&not_term, &not_whitespace)
        });

        let (index_start, index_end) = join(
            || index_of_unchecked(k, &found, |_, x| x.clone()),
            || rindex_of_unchecked(k, &found, |_, x| x.clone()),
        );

        // Truncate end.
        let val_add_1 = k.k.scalar_add_parallelized(&index_end.val, 1);
        let i = if_then_else_zero(k, &index_end.is_some, &val_add_1);
        let s = self.truncate(k, &i);

        // Truncate start.
        let i = if_then_else_zero(k, &index_start.is_some, &index_start.val);
        s.substr_from(k, &i)
    }

    /// Returns a copy of `self` where the start of `self` is stripped if it is
    /// equal to `s`.
    pub fn strip_prefix(&self, k: &ServerKey, s: &FheString) -> FheOption<FheString> {
        let b = self.substr_eq(k, 0, s);
        let index = s.len(k);
        let stripped = self.substr_from(k, &index);
        FheOption {
            is_some: b,
            val: stripped,
        }
    }

    /// Returns a copy of `self` where the end of `self` is stripped if it is
    /// equal to `s`.
    pub fn strip_suffix(&self, k: &ServerKey, s: &FheString) -> FheOption<FheString> {
        let found = self.rfind(k, s);
        let stripped = self.truncate(k, &found.val);

        // is_some = found.is_some && found.val + s_len == self_len
        let self_len = self.len(k);
        let s_len = s.len(k);
        let i_add_slen = k.k.add_parallelized(&found.val, &s_len);
        let i_add_slen_eq_selflen = k.k.eq_parallelized(&i_add_slen, &self_len);
        let is_some = k.k.boolean_bitand(&found.is_some, &i_add_slen_eq_selflen);

        FheOption {
            is_some,
            val: stripped,
        }
    }

    /// Returns `self[..index]`.
    pub fn truncate(&self, k: &ServerKey, index: &FheUsize) -> FheString {
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(i, c)| {
                // a[i] = i < index ? a[i] : 0
                let i_lt_index = k.k.scalar_gt_parallelized(index, i as u64);
                let ai = if_then_else_zero(k, &i_lt_index, &c.0);
                FheAsciiChar(ai)
            })
            .collect();
        FheString(v)
    }
}
