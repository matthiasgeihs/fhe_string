//! Functionality for string search.

use rayon::prelude::*;
use tfhe::integer::BooleanBlock;

use crate::{ciphertext::logic::all, server_key::ServerKey};

use super::{
    index_of_unchecked,
    logic::{any, if_then_else_bool, if_then_else_zero},
    rindex_of_unchecked, FheAsciiChar, FheOption, FheString, FheUsize,
};

impl FheString {
    /// Returns whether `self` contains the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn contains(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        let found = self.find_all(k, s);
        any(k, &found)
    }

    /// Returns the index of the first occurrence of `s`, if existent.
    pub fn find(&self, k: &ServerKey, s: &FheString) -> FheOption<FheUsize> {
        let found = self.find_all(k, s);

        // Determine index of first match.
        index_of_unchecked(k, &found, |_k, x| x.clone())
    }

    /// Returns a vector v of length self.max_len where the i-th entry is an
    /// encryption of 1 if the substring of self starting from i matches s, and
    /// an encryption of 0 otherwise.
    pub(super) fn find_all(&self, k: &ServerKey, s: &FheString) -> Vec<BooleanBlock> {
        (0..self.0.len() - 1)
            .into_par_iter()
            .map(|i| {
                log::trace!("find_all: at index {i}");
                self.substr_eq(k, i, s)
            })
            .collect::<Vec<_>>()
    }

    /// Returns a vector v of length self.max_len where `v[i] = p(self[i])`.
    pub(super) fn find_all_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> BooleanBlock,
    ) -> Vec<BooleanBlock> {
        self.0.par_iter().map(|c| p(k, c)).collect::<Vec<_>>()
    }

    /// Returns a vector v of length self.max_len where `v[i]` contains the
    /// index `j >= i` for which `p(v[j]) == 1`.
    pub(super) fn find_all_next_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> BooleanBlock,
    ) -> Vec<FheOption<FheUsize>> {
        self.0
            .par_iter()
            .enumerate()
            .map(|(i, _)| self.find_next_pred_unchecked(k, i, p))
            .collect::<Vec<_>>()
    }

    /// Similar to `find_all`, but zeros out matches that are overlapped by
    /// preceding matches.
    pub(super) fn find_all_non_overlapping(
        &self,
        k: &ServerKey,
        s: &FheString,
    ) -> Vec<BooleanBlock> {
        let matches = self.find_all(k, s);
        let s_len = s.len(k);

        // Zero out matches that are overlapped by preceding matches.
        /*
        in_match = 0
        j = 0
        for i in 0..matches.len:
            if in_match:
                matches[i] = 0
            else:
                in_match = matches[i]
                j = 0
            j += 1
            in_match = in_match && j < s.len
         */
        let mut in_match = k.k.create_trivial_boolean_block(false);
        let mut j = FheUsize::new_trivial(k, 0);
        matches
            .iter()
            .map(|mi| {
                // (matches[i], in_match, j) = in_match ? (0, in_match, j) : (matches[i], matches[i], 0)
                let mi_out =
                    if_then_else_bool(k, &in_match, &k.k.create_trivial_boolean_block(false), mi);
                j = if_then_else_zero(k, &in_match, &j);
                in_match = if_then_else_bool(k, &in_match, &in_match, mi);

                // j += 1
                k.k.scalar_add_assign_parallelized(&mut j, 1u8);

                // in_match = in_match && j < s.len
                let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
                in_match = k.k.boolean_bitand(&in_match, &j_lt_slen);

                mi_out
            })
            .collect::<Vec<_>>()
    }

    /// Similar to `find_all`, but zeros out matches that are overlapped by
    /// preceding matches, in reverse order.
    pub(super) fn rfind_all_non_overlapping(
        &self,
        k: &ServerKey,
        s: &FheString,
    ) -> Vec<BooleanBlock> {
        let matches = self.find_all(k, s);
        let s_len = s.len(k);

        // Zero out matches that are overlapped by preceding matches.
        /*
        j = 1
        for i in (0..matches.len).reverse():
            if j < s.len:
                matches[i] = 0
            else:
                j = matches[i] ? 0 : j
            j += 1
         */
        let zero = FheUsize::new_trivial(k, 0);
        let mut j = FheUsize::new_trivial(k, 1);
        matches
            .iter()
            .map(|mi| {
                // m[i] = j < s.len ? 0 : m[i]
                let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
                let mi =
                    if_then_else_bool(k, &j_lt_slen, &k.k.create_trivial_boolean_block(false), mi);

                // j = j >= s.len && m[i] ? 0 : j
                let j_lt_slen_and_mi = k.k.boolean_bitand(&j_lt_slen, &mi);
                j = k.k.if_then_else_parallelized(&j_lt_slen_and_mi, &zero, &j);

                // j += 1
                k.k.scalar_add_assign_parallelized(&mut j, 1u8);

                mi
            })
            .collect::<Vec<_>>()
    }

    /// Returns the index of the last occurence of `s`, if existent.
    pub fn rfind(&self, k: &ServerKey, s: &FheString) -> FheOption<FheUsize> {
        let found = self.find_all(k, s);

        // Determine index of first match in reverse order.
        let last = rindex_of_unchecked(k, &found, |_k, x| x.clone());

        // If empty pattern, return length. Otherwise return last index.
        let empty = s.is_empty(k);
        FheOption {
            is_some: if_then_else_bool(
                k,
                &empty,
                &k.k.create_trivial_boolean_block(true),
                &last.is_some,
            ),
            val: k
                .k
                .if_then_else_parallelized(&empty, &self.len(k), &last.val),
        }
    }

    /// Searches `self` for the first index `j >= i` with `p(self[j]) == 1`.
    ///
    /// Expects that `p` returns an encryption of either 0 or 1.
    pub(super) fn find_next_pred_unchecked(
        &self,
        k: &ServerKey,
        i: usize,
        p: fn(&ServerKey, &FheAsciiChar) -> BooleanBlock,
    ) -> FheOption<FheUsize> {
        // Search substring.
        let subvec = &self.0.get(i..).unwrap_or_default();
        let index = index_of_unchecked(k, subvec, p);
        // Add offset.
        let val = k.k.scalar_add_parallelized(&index.val, i as u64);
        FheOption {
            is_some: index.is_some,
            val,
        }
    }

    /// Searches `self` for the first index `i` with `p(self[i]) == 1`.
    pub fn find_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> BooleanBlock,
    ) -> FheOption<FheUsize> {
        index_of_unchecked(k, &self.0, p)
    }

    /// Searches `self` for the first index `i` with `p(self[i]) == 1` in
    /// reverse direction.
    pub fn rfind_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> BooleanBlock,
    ) -> FheOption<FheUsize> {
        rindex_of_unchecked(k, &self.0, p)
    }

    /// Returns whether `self` starts with the string `s`.
    pub fn starts_with(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        self.substr_eq(k, 0, s)
    }

    /// Returns whether `self` ends with the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn ends_with(&self, k: &ServerKey, s: &FheString) -> BooleanBlock {
        let v = (0..self.0.len() - 1)
            .into_par_iter()
            .map(|i| {
                log::trace!("ends_with: at index {i}");
                let a = self.0.get(i..).unwrap_or_default();

                // v[i] = a[i] == b[i] || b[i + 1] == 0
                let v = a
                    .par_iter()
                    .zip(&s.0)
                    .map(|(ai, bi)| {
                        let eq = k.k.eq_parallelized(&ai.0, &bi.0);
                        let is_term = &k.k.scalar_eq_parallelized(&ai.0, FheString::TERMINATOR);
                        k.k.boolean_bitor(&eq, is_term)
                    })
                    .collect::<Vec<_>>();
                all(k, &v)
            })
            .collect::<Vec<_>>();

        any(k, &v)
    }
}
