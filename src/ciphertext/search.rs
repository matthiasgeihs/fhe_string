use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::{
    ciphertext::{binary_if_then_else, binary_or, Uint},
    server_key::ServerKey,
};

use super::{binary_and, FheAsciiChar, FheOption, FheString};

impl FheString {
    /// Returns whether `self` contains the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn contains(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        self.find(k, s).is_some
    }

    /// Returns the index of the first occurrence of `s`, if existent.
    pub fn find(&self, k: &ServerKey, s: &FheString) -> FheOption<RadixCiphertext> {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        (0..self.0.len() - 1).for_each(|i| {
            log::debug!("find: at index {i}");

            // eq = self[i..i+s.len] == s
            let eq = self.substr_eq(k, i, s);

            // index = b ? index : (eq ? i : 0)
            let eq_mul_i = k.k.scalar_mul_parallelized(&eq, i as Uint);
            index = binary_if_then_else(k, &b, &index, &eq_mul_i);

            // b = b || eq
            b = binary_or(&k, &b, &eq);
        });
        FheOption {
            is_some: b,
            val: index,
        }
    }

    /// Returns a vector v of length self.max_len where the i-th entry is an
    /// encryption of 1 if the substring of self starting from i matches s, and
    /// an encryption of 0 otherwise.
    ///
    /// Formally: v[i] = self.substr_eq(k, i, s)
    pub(super) fn find_all(&self, k: &ServerKey, s: &FheString) -> Vec<RadixCiphertext> {
        (0..self.0.len() - 1)
            .into_par_iter()
            .map(|i| {
                log::debug!("find_all: at index {i}");
                self.substr_eq(k, i, s)
            })
            .collect::<Vec<_>>()
    }

    /// Returns a vector v of length self.max_len where `v[i] = p(self[i])`.
    ///
    /// `p` is expected to return an encryption of either 0 or 1.
    pub(super) fn find_all_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> Vec<RadixCiphertext> {
        self.0.par_iter().map(|c| p(k, c)).collect::<Vec<_>>()
    }

    /// Returns a vector v of length self.max_len where `v[i]` contains the
    /// index `j >= i` for which `p(v[j]) == 1`.
    pub(super) fn find_all_next_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> Vec<FheOption<RadixCiphertext>> {
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
    ) -> Vec<RadixCiphertext> {
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
        let mut in_match = k.create_zero();
        let mut j = k.create_zero();
        matches
            .iter()
            .map(|mi| {
                // (matches[i], in_match, j) = in_match ? (0, in_match, j) : (matches[i], matches[i], 0)
                let mi_out = binary_if_then_else(k, &in_match, &k.create_zero(), mi);
                j = binary_if_then_else(k, &in_match, &j, &k.create_zero());
                in_match = binary_if_then_else(k, &in_match, &in_match, mi);

                // j += 1
                k.k.scalar_add_assign_parallelized(&mut j, 1 as Uint);

                // in_match = in_match && j < s.len
                let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
                in_match = binary_and(k, &in_match, &j_lt_slen);

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
    ) -> Vec<RadixCiphertext> {
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
        let zero = k.create_zero();
        let mut j = k.create_one();
        matches
            .iter()
            .map(|mi| {
                // m[i] = j < s.len ? 0 : m[i]
                let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
                let mi = binary_if_then_else(k, &j_lt_slen, &zero, mi);

                // j = j >= s.len && m[i] ? 0 : j
                let j_lt_slen_and_mi = binary_and(k, &j_lt_slen, &mi);
                j = binary_if_then_else(k, &j_lt_slen_and_mi, &zero, &j);

                // j += 1
                k.k.scalar_add_assign_parallelized(&mut j, 1 as Uint);

                mi
            })
            .collect::<Vec<_>>()
    }

    /// Returns the index of the last occurence of `s`, if existent.
    pub fn rfind(&self, k: &ServerKey, s: &FheString) -> FheOption<RadixCiphertext> {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        (0..self.max_len()).rev().for_each(|i| {
            log::debug!("rfind: at index {i}");

            // eq = self[i..i+s.len] == s
            let eq = self.substr_eq(k, i, s);

            // index = b ? index : (eq ? i : 0)
            let eq_mul_i = k.k.scalar_mul_parallelized(&eq, i as Uint);
            index = binary_if_then_else(k, &b, &index, &eq_mul_i);

            // b = b || eq
            b = binary_or(&k, &b, &eq);
        });
        FheOption {
            is_some: b,
            val: index,
        }
    }

    /// Searches `self` for the first index `j >= i` with `p(self[j]) == 1`.
    ///
    /// Expects that `p` returns an encryption of either 0 or 1.
    pub(super) fn find_next_pred_unchecked(
        &self,
        k: &ServerKey,
        i: usize,
        p: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> FheOption<RadixCiphertext> {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        self.0
            .get(i..)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .for_each(|(j, c)| {
                let j = j + i;
                log::debug!("find_next_pred: at index {j}");

                // pj = p(self[j])
                let pj = p(k, c);

                // index = b ? index : (pj ? j : 0)
                let pj_mul_j = k.k.scalar_mul_parallelized(&pj, j as Uint);
                index = binary_if_then_else(k, &b, &index, &pj_mul_j);

                // b = b || pi
                b = binary_or(&k, &b, &pj);
            });
        FheOption {
            is_some: b,
            val: index,
        }
    }

    /// Searches `self` for the first index `i` with `p(self[i]) == 1`.
    ///
    /// Expects that `p` returns an encryption of either 0 or 1.
    pub fn find_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> FheOption<RadixCiphertext> {
        self.find_next_pred_unchecked(k, 0, p)
    }

    /// Searches `self` for the first index `i` with `p(self[i]) == 1` in
    /// reverse direction.
    ///
    /// Expects that `p` returns an encryption of either 0 or 1.
    pub fn rfind_pred_unchecked(
        &self,
        k: &ServerKey,
        p: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> FheOption<RadixCiphertext> {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        self.0.iter().enumerate().rev().for_each(|(i, c)| {
            log::debug!("rfind_char: at index {i}");

            // pi = p(self[i])
            let pi = p(k, c);

            // index = b ? index : (pi ? i : 0)
            let pi_mul_i = k.k.scalar_mul_parallelized(&pi, i as Uint);
            index = binary_if_then_else(k, &b, &index, &pi_mul_i);

            // b = b || pi
            b = binary_or(&k, &b, &pi);
        });
        FheOption {
            is_some: b,
            val: index,
        }
    }

    /// Returns whether `self` starts with the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn starts_with(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        self.substr_eq(k, 0, s)
    }

    /// Returns whether `self` ends with the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn ends_with(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let opti = self.rfind(k, s);

        // is_end = self.len == i + s.len
        let self_len = self.len(k);
        let s_len = s.len(k);
        let i_add_s_len = k.k.add_parallelized(&opti.val, &s_len);
        let is_end = k.k.eq_parallelized(&self_len, &i_add_s_len);

        // ends_with = contained && is_end
        binary_and(k, &opti.is_some, &is_end)
    }
}
