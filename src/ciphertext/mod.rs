use crate::{
    ciphertext::logic::{binary_not, binary_or},
    client_key::{ClientKey, Key},
    error::Error,
    server_key::ServerKey,
};
use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use self::logic::{binary_and, binary_if_then_else};

pub mod compare;
pub mod convert;
pub mod insert;
pub mod logic;
pub mod replace;
pub mod search;
pub mod split;
#[cfg(test)]
mod tests;
pub mod trim;

/// FheAsciiChar is a wrapper type for RadixCiphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheAsciiChar(pub(crate) RadixCiphertext);

/// FheString is a wrapper type for Vec<FheAsciiChar>. It is assumed to be
/// 0-terminated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheString(pub(crate) Vec<FheAsciiChar>);

/// Type used for scalar operations.
type Uint = u64;

impl FheString {
    /// ASCII value of the string termination character.
    const TERMINATOR: Uint = 0;

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
        } else if s.chars().find(|&x| x as Uint == Self::TERMINATOR).is_some() {
            return Err("string contains terminator character".into());
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

    /// Returns `self[index..]`.
    pub fn substr(&self, k: &ServerKey, index: &RadixCiphertext) -> FheString {
        let v = (0..self.0.len())
            .into_par_iter()
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
            .into_par_iter()
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

    /// Returns the maximum length of an FheString when using key `k`.
    pub fn max_len_with_key<K: Key>(k: &K) -> usize {
        k.max_int() - 1
    }

    /// Returns a copy of `self` padded so that it can hold `l` characters.
    ///
    /// # Panics
    /// Panics if l exceeds the maximum length.
    fn pad(&self, k: &ServerKey, l: usize) -> Self {
        if l > Self::max_len_with_key(k) {
            panic!("pad length exceeds maximum length")
        }

        let mut v = self.0.to_vec();
        let term = FheAsciiChar(k.create_value(Self::TERMINATOR));
        // l + 1 because of termination character.
        (0..l + 1 - self.0.len()).for_each(|_| v.push(term.clone()));
        FheString(v)
    }
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

/// Searches `v` for the first index `i` with `p(v[i]) == 1`.
///
/// Expects that `p` returns an encryption of either 0 or 1.
pub fn index_of_unchecked<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> RadixCiphertext,
) -> FheOption<RadixCiphertext> {
    index_of_unchecked_with_options(k, v, p, false)
}

/// Searches `v` for the last index `i` with `p(v[i]) == 1`.
///
/// Expects that `p` returns an encryption of either 0 or 1.
pub fn rindex_of_unchecked<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> RadixCiphertext,
) -> FheOption<RadixCiphertext> {
    index_of_unchecked_with_options(k, v, p, true)
}

/// Searches `v` for the first index `i` with `p(v[i]) == 1`. If `reverse`,
/// searches in reverse direction.
///
/// Expects that `p` returns an encryption of either 0 or 1.
fn index_of_unchecked_with_options<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> RadixCiphertext,
    reverse: bool,
) -> FheOption<RadixCiphertext> {
    let zero = k.create_zero();
    let mut b = zero.clone(); // Pattern contained.
    let mut index = zero.clone(); // Pattern index.

    let items: Vec<_> = if reverse {
        v.iter().enumerate().rev().collect()
    } else {
        v.iter().enumerate().collect()
    };

    // Evaluate predicate `p` on each element of `v`.
    let p_eval: Vec<_> = items.par_iter().map(|(i, x)| (i, p(k, x))).collect();

    // Find first index for which predicate evaluated to 1.
    p_eval.into_iter().for_each(|(i, pi)| {
        log::debug!("index_of_opt_unchecked: at index {i}");

        // index = b ? index : (pi ? i : 0)
        let pi_mul_i = k.k.scalar_mul_parallelized(&pi, *i as Uint);
        index = binary_if_then_else(k, &b, &index, &pi_mul_i);

        // b = b || pi
        b = binary_or(&k, &b, &pi);
    });

    FheOption {
        is_some: b,
        val: index,
    }
}

pub struct FheOption<T> {
    pub is_some: RadixCiphertext,
    pub val: T,
}
