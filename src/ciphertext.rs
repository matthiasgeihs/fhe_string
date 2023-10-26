use crate::{
    client_key::{ClientKey, Key},
    error::Error,
    server_key::ServerKey,
};
use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

/// FheAsciiChar is a wrapper type for RadixCiphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheAsciiChar(pub(crate) RadixCiphertext);

impl FheAsciiChar {
    const CASE_DIFF: Uint = 32;

    /// Returns whether this is a whitespace character.
    pub fn is_whitespace(&self, k: &ServerKey) -> RadixCiphertext {
        // Whitespace characters: 9 (Horizontal tab), 10 (Line feed), 11
        // (Vertical tab), 12 (Form feed), 13 (Carriage return), 32 (Space)

        // (9 <= c <= 13) || c == 32
        let c_geq_9 = k.k.scalar_ge_parallelized(&self.0, 9 as Uint);
        let c_leq_13 = k.k.scalar_le_parallelized(&self.0, 13 as Uint);
        let c_geq_9_and_c_leq_13 = k.k.mul_parallelized(&c_geq_9, &c_leq_13);
        let c_eq_32 = k.k.scalar_eq_parallelized(&self.0, 32 as Uint);
        binary_or(k, &c_geq_9_and_c_leq_13, &c_eq_32)
    }

    /// Returns whether `self` is uppercase.
    pub fn is_uppercase(&self, k: &ServerKey) -> RadixCiphertext {
        // (65 <= c <= 90)
        let c_geq_65 = k.k.scalar_ge_parallelized(&self.0, 65 as Uint);
        let c_leq_90 = k.k.scalar_le_parallelized(&self.0, 90 as Uint);
        k.k.mul_parallelized(&c_geq_65, &c_leq_90)
    }

    /// Returns whether `self` is lowercase.
    pub fn is_lowercase(&self, k: &ServerKey) -> RadixCiphertext {
        // (97 <= c <= 122)
        let c_geq_97 = k.k.scalar_ge_parallelized(&self.0, 97 as Uint);
        let c_leq_122 = k.k.scalar_le_parallelized(&self.0, 122 as Uint);
        k.k.mul_parallelized(&c_geq_97, &c_leq_122)
    }

    /// Returns the lowercase representation of `self`.
    pub fn to_lowercase(&self, k: &ServerKey) -> FheAsciiChar {
        // c + (c.uppercase ? 32 : 0)
        let ucase = self.is_uppercase(k);
        let ucase_mul_32 = k.k.scalar_mul_parallelized(&ucase, Self::CASE_DIFF);
        let lcase = k.k.add_parallelized(&self.0, &ucase_mul_32);
        FheAsciiChar(lcase)
    }

    /// Returns the uppercase representation of `self`.
    pub fn to_uppercase(&self, k: &ServerKey) -> FheAsciiChar {
        // c - (c.lowercase ? 32 : 0)
        let lcase = self.is_lowercase(k);
        let lcase_mul_32 = k.k.scalar_mul_parallelized(&lcase, Self::CASE_DIFF);
        let ucase = k.k.sub_parallelized(&self.0, &lcase_mul_32);
        FheAsciiChar(ucase)
    }
}

/// FheString is a wrapper type for Vec<FheAsciiChar>. It is assumed to be
/// 0-terminated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheString(pub(crate) Vec<FheAsciiChar>);

/// Type used for scalar operations.
type Uint = u64;

impl FheString {
    /// Creates a new FheString from an ascii string using the provided key. The
    /// input string must only contain ascii characters and must not contain any
    /// zero values. The result is padded to the specified length.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to be encrypted.
    /// * `k` - The client key.
    /// * `l` - The length to pad to.
    pub fn new(k: &ClientKey, s: &str, l: usize) -> Result<Self, Error> {
        if !s.is_ascii() {
            return Err("string is not ascii".into());
        } else if s.chars().find(|&x| x as u8 == 0).is_some() {
            return Err("string contains 0 char".into());
        } else if s.len() > Self::max_len_with_key(k) {
            return Err("string length exceeds maximum length".into());
        } else if l > Self::max_len_with_key(k) {
            return Err("pad length exceeds maximum length".into());
        } else if l < s.len() {
            return Err("string length exceeds pad length".into());
        }

        // Encrypt characters.
        let mut fhe_chars = s
            .chars()
            .map(|c| {
                let ct = k.0.encrypt(c as u8);
                FheAsciiChar(ct)
            })
            .collect::<Vec<_>>();

        // Append zero char.
        let zero = k.0.encrypt(0u8);
        let zero = FheAsciiChar(zero);
        fhe_chars.push(zero.clone());

        // Pad to length.
        (0..l + 1 - fhe_chars.len()).for_each(|_| fhe_chars.push(zero.clone()));

        Ok(FheString(fhe_chars))
    }

    pub fn decrypt(&self, k: &ClientKey) -> String {
        let chars = self
            .0
            .iter()
            .map(|c| k.0.decrypt::<u8>(&c.0))
            .filter(|&c| c != 0u8)
            .collect::<Vec<_>>();
        String::from_utf8(chars).unwrap()
    }

    /// Returns the length of `self`.
    pub fn len(&self, k: &ServerKey) -> RadixCiphertext {
        // l = sum_{i in 1..self.len} (self[i-1] != 0 && self[i] == 0) * i
        let v = self
            .0
            .par_windows(2)
            .enumerate()
            .map(|(i_sub_1, pair)| {
                log::debug!("len: at index {i_sub_1}");
                let self_isub1 = &pair[0];
                let self_i = &pair[1];
                let self_isub1_neq_0 = k.k.scalar_ne_parallelized(&self_isub1.0, 0);
                let self_i_eq_0 = k.k.scalar_eq_parallelized(&self_i.0, 0);
                let b = binary_and(k, &self_isub1_neq_0, &self_i_eq_0);
                let i = i_sub_1 + 1;
                k.k.scalar_mul_parallelized(&b, i as Uint)
            })
            .collect::<Vec<_>>();

        k.k.unchecked_sum_ciphertexts_vec_parallelized(v)
            .unwrap_or(k.create_zero())
    }

    /// Returns an upper bound on the length of `self`.
    pub fn max_len(&self) -> usize {
        // Substract 1 because strings are 0-terminated.
        self.0.len() - 1
    }

    /// Returns whether `self` contains the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn contains(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let (b, _) = self.find(k, s);
        b
    }

    /// If `self` contains `s`, returns (1, i), where i is the index of the
    /// first occurrence of `s`. Otherwise, returns (0, 0).
    pub fn find(&self, k: &ServerKey, s: &FheString) -> (RadixCiphertext, RadixCiphertext) {
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
        (b, index)
    }

    /// Returns a vector v of length self.vlen-1 where the i-th entry is an
    /// encryption of 1 if the substring of self starting from i matches s, and
    /// an encryption of 0 otherwise.
    ///
    /// Formally: v[i] = self.substr_eq(k, i, s)
    pub fn find_all(&self, k: &ServerKey, s: &FheString) -> Vec<RadixCiphertext> {
        (0..self.0.len() - 1)
            .into_par_iter()
            .map(|i| {
                log::debug!("find_all: at index {i}");
                self.substr_eq(k, i, s)
            })
            .collect::<Vec<_>>()
    }

    /// Similar to `find_all`, but zeros out matches that are overlapped by
    /// preceding matches.
    fn find_all_non_overlapping(&self, k: &ServerKey, s: &FheString) -> Vec<RadixCiphertext> {
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

    /// If `self` contains `s`, returns (1, i), where i is the index of the
    /// last occurrence of `s`. Otherwise, returns (0, 0).
    pub fn rfind(&self, k: &ServerKey, s: &FheString) -> (RadixCiphertext, RadixCiphertext) {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        (0..self.0.len() - s.0.len() + 1).rev().for_each(|i| {
            log::debug!("rfind: at index {i}");

            // eq = self[i..i+s.len] == s
            let eq = self.substr_eq(k, i, s);

            // index = b ? index : (eq ? i : 0)
            let eq_mul_i = k.k.scalar_mul_parallelized(&eq, i as Uint);
            index = binary_if_then_else(k, &b, &index, &eq_mul_i);

            // b = b || eq
            b = binary_or(&k, &b, &eq);
        });
        (b, index)
    }

    /// Searches `self` for a match with `m`. Returns (1, i) if a match was
    /// found, where i is the index of the first match. Otherwise, returns (0,
    /// 0).
    pub fn find_char(
        &self,
        k: &ServerKey,
        m: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        self.0.iter().enumerate().for_each(|(i, c)| {
            log::debug!("find_char: at index {i}");

            // mi = m(self[i])
            let mi = m(k, c);

            // index = b ? index : (mi ? i : 0)
            let mi_mul_i = k.k.scalar_mul_parallelized(&mi, i as Uint);
            index = binary_if_then_else(k, &b, &index, &mi_mul_i);

            // b = b || mi
            b = binary_or(&k, &b, &mi);
        });
        (b, index)
    }

    /// Searches `self` for a match with `m` in reverse direction. Returns (1,
    /// i) if a match was found, where i is the index of the last match.
    /// Otherwise, returns (0, 0).
    pub fn rfind_char(
        &self,
        k: &ServerKey,
        m: fn(&ServerKey, &FheAsciiChar) -> RadixCiphertext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.
        let mut index = zero.clone(); // Pattern index.

        self.0.iter().enumerate().rev().for_each(|(i, c)| {
            log::debug!("rfind_char: at index {i}");

            // mi = m(self[i])
            let mi = m(k, c);

            // index = b ? index : (mi ? i : 0)
            let mi_mul_i = k.k.scalar_mul_parallelized(&mi, i as Uint);
            index = binary_if_then_else(k, &b, &index, &mi_mul_i);

            // b = b || mi
            b = binary_or(&k, &b, &mi);
        });
        (b, index)
    }

    /// Returns whether `self` starts with the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn starts_with(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        self.substr_eq(k, 0, s)
    }

    /// Returns whether `self` ends with the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn ends_with(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let (contained, i) = self.find(k, s);

        // is_end = self.len == i + s.len
        let self_len = self.len(k);
        let s_len = s.len(k);
        let i_add_s_len = k.k.add_parallelized(&i, &s_len);
        let is_end = k.k.eq_parallelized(&self_len, &i_add_s_len);

        // ends_with = contained && is_end
        k.k.mul_parallelized(&contained, &is_end)
    }

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
        let l = if self.0.len() > s.0.len() {
            self.0.len()
        } else {
            s.0.len()
        };
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        let mut is_eq = k.create_one();

        // is_eq = is_eq && ai == bi
        a.0.iter().zip(b.0).for_each(|(ai, bi)| {
            let ai_eq_bi = k.k.eq_parallelized(&ai.0, &bi.0);
            is_eq = k.k.mul_parallelized(&is_eq, &ai_eq_bi);
        });
        is_eq
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
        let l = if self.0.len() > s.0.len() {
            self.0.len()
        } else {
            s.0.len()
        };
        let a = self.pad(k, l);
        let b = s.pad(k, l);

        let mut is_lt = k.create_zero();
        let mut is_eq = k.create_one();

        // is_lt = is_lt || ai < bi
        a.0.iter().zip(b.0).for_each(|(ai, bi)| {
            // is_lt = is_lt || ai < bi && is_eq
            let ai_lt_bi = k.k.lt_parallelized(&ai.0, &bi.0);
            let ai_lt_bi_and_eq = binary_and(k, &ai_lt_bi, &is_eq);
            is_lt = binary_or(k, &is_lt, &ai_lt_bi_and_eq);

            // is_eq = is_eq && ai == bi
            let ai_eq_bi = k.k.le_parallelized(&ai.0, &bi.0);
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
    pub fn eq_ignore_case(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let one = k.create_one();

        // Pad to same length.
        let l = if self.0.len() > s.0.len() {
            self.0.len()
        } else {
            s.0.len()
        };
        let a = self.pad(k, l);
        let b = s.pad(k, l);

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
        let a = FheString(self.0[i..].to_vec());
        let b = s;

        let mut is_equal = k.create_one();
        let mut b_terminated = k.create_zero();

        a.0.iter().zip(&b.0).for_each(|(ai, bi)| {
            // b_terminated = b_terminated || bi == 0
            let bi_eq_0 = k.k.scalar_eq_parallelized(&bi.0, 0);
            b_terminated = binary_or(k, &b_terminated, &bi_eq_0);

            // is_equal = is_equal && (ai == bi || b_terminated)
            let ai_eq_bi = k.k.eq_parallelized(&ai.0, &bi.0);
            let ai_eq_bi_or_bterm = binary_or(k, &ai_eq_bi, &b_terminated);
            is_equal = k.k.mul_parallelized(&is_equal, &ai_eq_bi_or_bterm);
        });
        is_equal
    }

    /// Returns `self[i..]` where `i` is the index of the first non-whitespace
    /// character.
    pub fn trim_start(&self, k: &ServerKey) -> FheString {
        let (_, i) = self.find_char(k, |k, c| {
            let is_whitespace = c.is_whitespace(k);
            binary_not(k, &is_whitespace)
        });

        self.substr(k, &i)
    }

    /// Returns `self[..i+1]` where `i` is the index of the last non-whitespace
    /// character.
    pub fn trim_end(&self, k: &ServerKey) -> FheString {
        let (_, i) = self.rfind_char(k, |k, c| {
            let is_zero = k.k.scalar_eq_parallelized(&c.0, 0 as Uint);
            let not_zero = binary_not(k, &is_zero);
            let is_whitespace = c.is_whitespace(k);
            let not_whitespace = binary_not(k, &is_whitespace);
            k.k.mul_parallelized(&not_zero, &not_whitespace)
        });

        let i = k.k.scalar_add_parallelized(&i, 1 as Uint);
        self.truncate(k, &i)
    }

    /// Returns `self[i..j+1]` where `i` is the index of the first
    /// non-whitespace character and `j` is the index of the last non-whitespace
    /// character.
    pub fn trim(&self, k: &ServerKey) -> FheString {
        let ltrim = self.trim_start(k);
        ltrim.trim_end(k)
    }

    /// Returns a copy of `self` where the start of `self` is stripped if it is
    /// equal to `s`.
    pub fn strip_prefix(&self, k: &ServerKey, s: &FheString) -> FheString {
        let b = self.substr_eq(k, 0, s);
        let index = s.len(k);
        let b_mul_index = k.k.mul_parallelized(&b, &index);
        self.substr(k, &b_mul_index)
    }

    /// Returns a copy of `self` where the end of `self` is stripped if it is
    /// equal to `s`.
    pub fn strip_suffix(&self, k: &ServerKey, s: &FheString) -> FheString {
        let (b, i) = self.rfind(k, s);
        let self_len = self.len(k);
        let s_len = s.len(k);

        // index = b && (i + s_len == self_len) ? i : self_len
        let i_add_slen = k.k.add_parallelized(&i, &s_len);
        let i_add_slen_eq_selflen = k.k.eq_parallelized(&i_add_slen, &self_len);
        let b_and_i_add_slen_eq_selflen = binary_and(k, &b, &i_add_slen_eq_selflen);
        let index = binary_if_then_else(k, &b_and_i_add_slen_eq_selflen, &i, &self_len);

        self.truncate(k, &index)
    }

    /// Returns a copy of `self` where uppercase characters have been replaced
    /// by their lowercase counterparts.
    pub fn to_lowercase(&self, k: &ServerKey) -> FheString {
        let v = self.0.iter().map(|c| c.to_lowercase(k)).collect();
        FheString(v)
    }

    /// Returns a copy of `self` where lowercase characters have been replaced
    /// by their uppercase counterparts.
    pub fn to_uppercase(&self, k: &ServerKey) -> FheString {
        let v = self.0.iter().map(|c| c.to_uppercase(k)).collect();
        FheString(v)
    }

    /// Returns `self[index..]`.
    pub fn substr(&self, k: &ServerKey, index: &RadixCiphertext) -> FheString {
        let v = (0..self.0.len())
            .par_bridge()
            .map(|i| {
                log::debug!("substr: at index {i}");

                // a[i] = a[i + index]
                let i_add_index = k.k.scalar_add_parallelized(index, i as Uint);
                self.char_at(k, &i_add_index)
            })
            .collect();
        FheString(v)
    }

    /// Returns `self[start..end]`.
    pub fn substr_end(
        &self,
        k: &ServerKey,
        start: &RadixCiphertext,
        end: &RadixCiphertext,
    ) -> FheString {
        let v = (0..self.0.len())
            .par_bridge()
            .map(|i| {
                log::debug!("substr_end: at index {i}");

                // a[i] = i + index < end ? a[i + index] : 0
                let i_add_index = k.k.scalar_add_parallelized(start, i as Uint);
                let i_add_index_lt_end = k.k.lt_parallelized(&i_add_index, end);
                let self_i_add_index = self.char_at(k, &i_add_index);
                let ai = binary_if_then_else(
                    k,
                    &i_add_index_lt_end,
                    &self_i_add_index.0,
                    &k.create_zero(),
                );
                FheAsciiChar(ai)
            })
            .collect();
        FheString(v)
    }

    /// Returns `self[..index]`.
    pub fn truncate(&self, k: &ServerKey, index: &RadixCiphertext) -> FheString {
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(i, c)| {
                // a[i] = i < index ? a[i] : 0
                let i_lt_index = k.k.scalar_gt_parallelized(index, i as Uint);
                FheAsciiChar(k.k.mul_parallelized(&i_lt_index, &c.0))
            })
            .collect();
        FheString(v)
    }

    /// Returns the character at the given index. Returns 0 if the index is out
    /// of bounds.
    pub fn char_at(&self, k: &ServerKey, i: &RadixCiphertext) -> FheAsciiChar {
        // ai = i == 0 ? a[0] : 0 + ... + i == n ? a[n] : 0
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(j, aj)| {
                log::debug!("char_at: at index {j}");

                // i == j ? a[j] : 0
                let i_eq_j = k.k.scalar_eq_parallelized(i, j as Uint);
                let i_eq_j_mul_aj = k.k.mul_parallelized(&i_eq_j, &aj.0);
                i_eq_j_mul_aj
            })
            .collect::<Vec<_>>();

        let ai =
            k.k.unchecked_sum_ciphertexts_slice_parallelized(&v)
                .unwrap_or(k.create_zero());
        FheAsciiChar(ai)
    }

    /// Returns `self + s`.
    pub fn append(&self, k: &ServerKey, s: &FheString) -> FheString {
        let self_len = self.len(k);
        self.insert(k, &self_len, s)
    }

    /// Returns `self` repeated `n` times up to length `l`.
    pub fn repeat(&self, k: &ServerKey, n: &RadixCiphertext, l: usize) -> FheString {
        let l = std::cmp::min(l, Self::max_len_with_key(k));
        let self_len = self.len(k);
        let n_mul_self_len = k.k.mul_parallelized(n, &self_len);
        let mut v = (0..l)
            .map(|i| {
                log::debug!("repeat: at index {i}");

                // v[i] = i < n * self.len ? self[i % self.len] : 0
                let i_radix = k.create_value(i as Uint);
                let i_lt_n_mul_self_len = k.k.lt_parallelized(&i_radix, &n_mul_self_len);
                let i_mod_self_len = k.k.rem_parallelized(&i_radix, &self_len);
                let self_i_mod_self_len = self.char_at(k, &i_mod_self_len);
                let vi = binary_if_then_else(
                    k,
                    &i_lt_n_mul_self_len,
                    &self_i_mod_self_len.0,
                    &k.create_zero(),
                );
                FheAsciiChar(vi)
            })
            .collect::<Vec<_>>();

        // Append 0 to terminate string.
        v.push(FheAsciiChar(k.create_zero()));
        FheString(v)
    }

    /// Returns `self` where `p` is replaced by `s` up to length `l`.
    pub fn replace(&self, k: &ServerKey, p: &FheString, s: &FheString, l: usize) -> FheString {
        self.replace_nopt(k, p, s, None, l)
    }

    /// Returns `self` where `p` is replaced by `s` up to `n_max` times and the
    /// output has maximum length `l`.
    pub fn replacen(
        &self,
        k: &ServerKey,
        p: &FheString,
        s: &FheString,
        n_max: &RadixCiphertext,
        l: usize,
    ) -> FheString {
        self.replace_nopt(k, p, s, Some(n_max), l)
    }

    /// Returns `self` where `p` is replaced by `s` up to `n_max` times and the
    /// output has maximum length `l`. If `n_max` is None, then there is not
    /// limit on the number of replacements.
    fn replace_nopt(
        &self,
        k: &ServerKey,
        p: &FheString,
        s: &FheString,
        n_max: Option<&RadixCiphertext>,
        l: usize,
    ) -> FheString {
        let l = std::cmp::min(l, Self::max_len_with_key(k));

        // found[i] = self.substr_eq(i, p)
        let found = self.find_all(k, p);
        let p_len = p.len(k);
        let s_len = s.len(k);
        let len_diff = k.k.sub_parallelized(&p_len, &s_len);

        /*
        (in_match, j, n) = (false, 0, 0)
        for i in 0..l:
            c = i + n * (p.len - s.len)
            (in_match, j, n) = in_match && j < s.len ? (in_match, j, n) : (found[c] && n < n_max, 0, n + found[c])
            v[i] = in_match ? s[j] : self[c]
            j += 1
         */
        let mut in_match = k.create_zero();
        let mut j = k.create_zero();
        let mut n = k.create_zero();
        let mut v = Vec::<FheAsciiChar>::new();
        let zero = k.create_zero();
        (0..l).for_each(|i| {
            log::debug!("replace_nopt: at index {i}");

            // c = i + n * len_diff
            let n_mul_lendiff = k.k.mul_parallelized(&n, &len_diff);
            let c = k.k.scalar_add_parallelized(&n_mul_lendiff, i as Uint);

            let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
            let match_and_jltslen = binary_and(k, &in_match, &j_lt_slen);

            let found_c = element_at(k, &found, &c);
            let foundc_and_n_lt_nmax = match n_max {
                Some(n_max) => {
                    let n_lt_nmax = k.k.lt_parallelized(&n, n_max);
                    binary_and(k, &found_c, &n_lt_nmax)
                }
                None => found_c,
            };
            let n_add_found_c = k.k.add_parallelized(&n, &foundc_and_n_lt_nmax);

            in_match = binary_if_then_else(k, &match_and_jltslen, &in_match, &foundc_and_n_lt_nmax);
            j = binary_if_then_else(k, &match_and_jltslen, &j, &zero);
            n = binary_if_then_else(k, &match_and_jltslen, &n, &n_add_found_c);

            let sj = s.char_at(k, &j).0;
            let self_c = self.char_at(k, &c).0;
            let vi = binary_if_then_else(k, &in_match, &sj, &self_c);
            v.push(FheAsciiChar(vi));

            j = k.k.scalar_add_parallelized(&j, 1 as Uint);
        });

        // Append 0 to terminate string.
        v.push(FheAsciiChar(k.create_zero()));
        FheString(v)
    }

    /// Returns a copy of `self` where `s` is inserted at the given index.
    ///
    /// # Panics
    /// Panics on index out of bounds.
    pub fn insert(&self, k: &ServerKey, index: &RadixCiphertext, s: &FheString) -> FheString {
        let a = self;
        let b = s;
        let l = std::cmp::min(a.0.len() + b.0.len() - 2, Self::max_len_with_key(k));
        let b_len = b.len(k);

        let mut v = (0..l)
            .par_bridge()
            .map(|i| {
                // v[i] = i < index ? a[i] : (i < index + b.len ? b[i - index] : a[i - index])

                // c0 = i < index
                let c0 = k.k.scalar_gt_parallelized(index, i as Uint);

                // c1 = a[i]
                let c1 = &a.0[i % a.0.len()].0;

                // c2 = i < index + b.len ? b[i - index] : a[i - index]
                let index_add_blen = k.k.add_parallelized(index, &b_len);
                let i_leq_index_add_blen = k.k.scalar_gt_parallelized(&index_add_blen, i as Uint);
                let i_radix = k.create_value(i as Uint);
                let i_sub_index = k.k.sub_parallelized(&i_radix, &index);
                let b_i_sub_index = b.char_at(k, &i_sub_index);
                let a_i_sub_index = a.char_at(k, &i_sub_index);
                let c2 = binary_if_then_else(
                    k,
                    &i_leq_index_add_blen,
                    &b_i_sub_index.0,
                    &a_i_sub_index.0,
                );

                // c = c0 ? c1 : c2
                let c = binary_if_then_else(k, &c0, c1, &c2);
                FheAsciiChar(c)
            })
            .collect::<Vec<_>>();

        // Append 0 to terminate string.
        v.push(FheAsciiChar(k.create_zero()));
        FheString(v)
    }

    /// Returns the maximum length of an FheString when using key `k`.
    pub fn max_len_with_key<K: Key>(k: &K) -> usize {
        k.max_int() - 1
    }

    /// Returns a copy of `self` padded to the given length.
    ///
    /// # Panics
    /// Panics if l exceeds the maximum length.
    fn pad(&self, k: &ServerKey, l: usize) -> Self {
        if l > Self::max_len_with_key(k) {
            panic!("pad length exceeds maximum length")
        }

        let mut v = self.0.to_vec();
        let zero = FheAsciiChar(k.create_zero());
        (0..l - self.0.len()).for_each(|_| v.push(zero.clone()));
        FheString(v)
    }
}

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

// Return the value of v[i] or 0 if i is out of bounds.
pub fn element_at(k: &ServerKey, v: &[RadixCiphertext], i: &RadixCiphertext) -> RadixCiphertext {
    // ai = i == 0 ? a[0] : 0 + ... + i == n ? a[n] : 0
    let v = v
        .par_iter()
        .enumerate()
        .map(|(j, aj)| {
            log::debug!("element_at: at index {j}");

            // i == j ? a[j] : 0
            let i_eq_j = k.k.scalar_eq_parallelized(i, j as Uint);
            let i_eq_j_mul_aj = k.k.mul_parallelized(&i_eq_j, &aj);
            i_eq_j_mul_aj
        })
        .collect::<Vec<_>>();

    k.k.unchecked_sum_ciphertexts_slice_parallelized(&v)
        .unwrap_or(k.create_zero())
}

fn playground() {
    println!("{:?}", "xxx".split("x").collect::<Vec<_>>()); // = ["", "", "", ""]
    println!("{:?}", "xxx".split_inclusive("x").collect::<Vec<_>>()); // = ["x", "x", "x"]

    println!("{:?}", "axa".split("x").collect::<Vec<_>>()); // = ["a", "a"]
    println!("{:?}", "axa".split_inclusive("x").collect::<Vec<_>>()); // = ["ax", "a"]

    /*
    ["", "", "", ""] = {
        s: "xxx",
        v: [
            0: (1, 0),
            1: (1, 0),
            2: (1, 0),
            3: (1, 0),
        ],
    }

    ["x", "x", "x"] = {
        s: "xxx",
        v: [
            0: (1, 1),
            1: (1, 1),
            2: (1, 1),
            3: (0, 0),
        ],
    }

    ["a", "a"] = {
        s: "axa",
        v: [
            0: (1, 1),
            1: (0, 0),
            2: (1, 1),
            3: (0, 0),
        ],
    }

    ["ax", "a"] = {
        s: "axa",
        v: [
            0: (1, 2),
            1: (0, 0),
            2: (1, 1),
            3: (0, 0),
        ],
    }
    */
}

/// An element of an `FheStringSliceVector`.
struct FheStringSlice {
    /// Defines whether this is an actual entry in a string slice vector. If
    /// this is zero, then this is just a dummy entry.
    is_start: RadixCiphertext,

    /// The end index of the string slice, exclusive.
    end: RadixCiphertext,
}

/// An encrypted vector of substrings of an encrypted reference string.
pub struct FheStringSliceVector {
    /// The reference string.
    s: FheString,

    /// The substring vector. For each character of the string, it indicates
    /// whether a substring starting from this character is contained in the
    /// vector and what the length of that substring is.
    ///
    /// Formally: for each i in 0..s.vlen: v[i] = (is_start_i, end_i)
    v: Vec<FheStringSlice>,
}

impl FheStringSliceVector {
    /// Returns the number of substrings contained in this vector.
    pub fn len(&self, k: &ServerKey) -> RadixCiphertext {
        let v = self
            .v
            .par_iter()
            .map(|vi| vi.is_start.clone())
            .collect::<Vec<_>>();
        k.k.unchecked_sum_ciphertexts_vec_parallelized(v)
            .unwrap_or(k.create_zero())
    }

    /// Returns `(1, self[i])`, where `self[i]` is the substring at index `i`,
    /// if it exists. Returns `(0, "")` otherwise.
    pub fn get(&self, k: &ServerKey, i: &RadixCiphertext) -> FheOption<FheString> {
        let mut n = k.create_zero();

        let init = FheOption {
            is_some: k.create_zero(),
            val: FheStringSlice {
                is_start: k.create_zero(), // This will hold the starting index.
                end: k.create_zero(),
            },
        };

        let slice = self.v.iter().enumerate().fold(init, |acc, (j, vi)| {
            // acc = i == n && vi.is_start ? (j, vi.end) : acc
            let i_eq_n = k.k.eq_parallelized(i, &n);
            let is_some = binary_and(k, &i_eq_n, &vi.is_start);
            let j_radix = k.create_value(j as Uint);
            let start = binary_if_then_else(k, &is_some, &j_radix, &acc.val.is_start);
            let end = binary_if_then_else(k, &is_some, &vi.end, &acc.val.end);
            let acc = FheOption {
                is_some,
                val: FheStringSlice {
                    is_start: start,
                    end,
                },
            };

            // n += 1
            k.k.add_assign_parallelized(&mut n, &vi.is_start);

            acc
        });

        let is_some = slice.is_some;
        let val = self.s.substr_end(k, &slice.val.is_start, &slice.val.end);
        FheOption { is_some, val }
    }

    /// Truncates `self` starting from index `i`.
    pub fn truncate(&mut self, k: &ServerKey, i: &RadixCiphertext) {
        /*
        n = 0
        for i in v.len:
            v[i] = v[i] if n < i else (0, 0)
            n += v[i].is_start
        */
        let mut n = k.create_zero();
        let zero = k.create_zero();
        self.v = self
            .v
            .iter()
            .map(|vi| {
                // n < i
                let n_lt_i = k.k.lt_parallelized(&n, &i);
                let is_start = binary_if_then_else(k, &n_lt_i, &vi.is_start, &zero);
                let end = binary_if_then_else(k, &n_lt_i, &vi.end, &zero);

                // n += v[i].is_start
                k.k.add_assign_parallelized(&mut n, &vi.is_start);

                FheStringSlice { is_start, end }
            })
            .collect::<Vec<_>>();
    }

    /// Truncate the last element if it is empty.
    fn truncate_last_if_empty(&mut self, k: &ServerKey) {
        let s_len = self.s.len(k);
        let mut b = k.create_one();
        let mut v = self
            .v
            .iter()
            .enumerate()
            .rev()
            .map(|(i, vi)| {
                log::debug!("truncate_last_if_empty: i = {}", i);

                // is_empty = vi.end <= i || s.len <= i
                let end_le_i = k.k.scalar_le_parallelized(&vi.end, i as Uint);
                let slen_le_i = k.k.scalar_le_parallelized(&s_len, i as Uint);
                let is_empty = binary_or(k, &end_le_i, &slen_le_i);

                // is_start = b && vi.is_start && is_empty ? 0 : vi.is_start
                let b_and_start = binary_and(k, &b, &vi.is_start);
                let b_and_start_and_empty = binary_and(k, &b_and_start, &is_empty);
                let is_start =
                    binary_if_then_else(k, &b_and_start_and_empty, &k.create_zero(), &vi.is_start);

                // b = b && !vi.is_start
                let not_start = binary_not(k, &vi.is_start);
                b = binary_and(k, &b, &not_start);

                FheStringSlice {
                    is_start,
                    end: vi.end.clone(),
                }
            })
            .collect::<Vec<_>>();
        v.reverse();
        self.v = v;
    }

    /// Expand the last slice to the length of the string.
    fn expand_last(&mut self, k: &ServerKey) {
        let mut b = k.create_one();
        let mut v = self
            .v
            .iter()
            .rev()
            .map(|vi| {
                // end = b && vi.is_start ? self.s.max_len : vi.end
                let b_and_start = binary_and(k, &b, &vi.is_start);
                let max_len = k.create_value(self.s.max_len() as Uint);
                let end = binary_if_then_else(k, &b_and_start, &max_len, &vi.end);

                // b = b && !vi.is_start
                let not_start = binary_not(k, &vi.is_start);
                b = binary_and(k, &b, &not_start);

                FheStringSlice {
                    is_start: vi.is_start.clone(),
                    end,
                }
            })
            .collect::<Vec<_>>();
        v.reverse();
        self.v = v;
    }

    /// Decrypts this vector.
    pub fn decrypt(&self, k: &ClientKey) -> Vec<String> {
        let s_dec = self.s.decrypt(k);
        self.v
            .iter()
            .enumerate()
            .filter_map(|(i, vi)| {
                let is_start = k.0.decrypt::<Uint>(&vi.is_start);
                match is_start {
                    0 => None,
                    _ => {
                        let end = k.0.decrypt::<Uint>(&vi.end) as usize;
                        let slice = s_dec.get(i..end).unwrap_or_default();
                        Some(slice.to_string())
                    }
                }
            })
            .collect()
    }
}

pub struct FheOption<T> {
    pub is_some: RadixCiphertext,
    pub val: T,
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// where the pattern is optionally included at the end of each substring.
pub fn split_inclusive_opt(
    k: &ServerKey,
    s: &FheString,
    p: &FheString,
    inclusive: bool,
) -> FheStringSliceVector {
    /*
    matches = s.find_all_non_overlapping(k, p);
    n = matches.len + 1
    next_match = n
    let substrings = (0..n).rev().map(|i| {
        is_start_i = i == 0 || matches[i - p.len]
        next_match = matches[i] ? i + (inclusive ? p.len : 0) : next_match
        end_i = next_match
    })
     */

    let matches = s.find_all_non_overlapping(k, p);
    let p_len = p.len(k);

    let n = s.0.len();
    let mut next_match = k.create_value((n - 1) as Uint);
    let zero = k.create_zero();
    let mut elems = (0..n)
        .rev()
        .map(|i| {
            log::debug!("split_inclusive_opt: at index {i}");

            // is_start_i = i == 0 || matches[i - p.len]
            let is_start = if i == 0 {
                k.create_one()
            } else {
                let i_radix = k.create_value(i as Uint);
                let i_sub_plen = k.k.sub_parallelized(&i_radix, &p_len);
                element_at(k, &matches, &i_sub_plen)
            };

            // next_match_target = i + (inclusive ? p.len : 0)
            let next_match_target = if inclusive {
                k.k.scalar_add_parallelized(&p_len, i as Uint)
            } else {
                k.create_value(i as Uint)
            };

            // next_match[i] = matches[i] ? next_match_target : next_match[i+1]
            let matches_i = matches.get(i).unwrap_or(&zero);
            next_match = binary_if_then_else(k, matches_i, &next_match_target, &next_match);

            let end = next_match.clone();
            FheStringSlice { is_start, end }
        })
        .collect::<Vec<_>>();
    elems.reverse();

    let mut v = FheStringSliceVector {
        s: s.clone(),
        v: elems,
    };

    // If inclusive, remove last element if empty.
    if inclusive {
        v.truncate_last_if_empty(k);
    }

    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings.
pub fn split(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    split_inclusive_opt(k, s, p, false)
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// where the pattern is included at the end of each substring.
pub fn split_inclusive(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    split_inclusive_opt(k, s, p, true)
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// of at most length `n`.
pub fn splitn(
    k: &ServerKey,
    s: &FheString,
    n: &RadixCiphertext,
    p: &FheString,
) -> FheStringSliceVector {
    let mut v = split(k, s, p);
    v.truncate(k, n);
    v.expand_last(k);
    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// where the last substring is skipped if empty.
pub fn split_terminator(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    let mut v = split(k, s, p);
    v.truncate_last_if_empty(k);
    v
}
