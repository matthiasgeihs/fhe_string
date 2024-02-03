//! Types and functionality for working with encrypted strings.

use std::{cmp, error::Error};

use crate::{
    ciphertext::logic::if_then_else_zero,
    client_key::{ClientKey, Key},
    server_key::ServerKey,
};
use rayon::prelude::*;
use tfhe::integer::{
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, RadixCiphertext,
    ServerKey as IntegerServerKey,
};

use self::logic::{any, scalar_if_then_else_zero};

mod compare;
mod convert;
mod insert;
mod logic;
mod replace;
mod search;
pub mod split;
#[cfg(test)]
mod tests;
mod trim;

/// FheAsciiChar is a wrapper type for RadixCiphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheAsciiChar(pub(crate) RadixCiphertext);

impl FheAsciiChar {
    // Creates an encryption of `c`.
    pub fn new(k: &ClientKey, c: u8) -> Self {
        Self(k.k.encrypt(c))
    }
}

/// FheString is a wrapper type for `Vec<FheAsciiChar>`. It is assumed to be
/// 0-terminated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheString(pub(crate) Vec<FheAsciiChar>);

impl FheString {
    /// ASCII value of the string termination character.
    const TERMINATOR: u8 = 0;

    /// Creates a new FheString from an ascii string using the provided key. The
    /// input string must only contain ascii characters and must not contain any
    /// zero values. The result is padded to the specified length.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to be encrypted.
    /// * `k` - The client key.
    /// * `l` - Optional length to pad to.
    pub fn new(k: &ClientKey, s: &str, l: Option<usize>) -> Result<Self, Box<dyn Error>> {
        if !s.is_ascii() {
            return Err("string is not ascii".into());
        } else if s.chars().any(|x| x as u8 == Self::TERMINATOR) {
            return Err("string contains terminator character".into());
        } else if s.len() > Self::max_len_with_key(k) {
            return Err("string length exceeds maximum length".into());
        } else if let Some(l) = l {
            if l > Self::max_len_with_key(k) {
                return Err("pad length exceeds maximum length".into());
            } else if l < s.len() {
                return Err("string length exceeds pad length".into());
            }
        }

        // Encrypt characters.
        let mut chars = s
            .chars()
            .map(|c| FheAsciiChar::new(k, c as u8))
            .collect::<Vec<_>>();

        // Append terminating character.
        let term = FheAsciiChar::new(k, Self::TERMINATOR);
        chars.push(term);

        // Optional: Pad to length.
        if let Some(l) = l {
            (0..l + 1 - chars.len()).for_each(|_| {
                let term = FheAsciiChar::new(k, Self::TERMINATOR);
                chars.push(term)
            });
        }

        Ok(FheString(chars))
    }

    /// Similar to `FheString::new`, but only creates a trivial encryption that
    /// does not actually hide the plaintext.
    pub fn new_trivial(k: &ServerKey, s: &str) -> Result<Self, Box<dyn Error>> {
        if !s.is_ascii() {
            return Err("string is not ascii".into());
        } else if s.chars().any(|x| x as u8 == Self::TERMINATOR) {
            return Err("string contains terminator character".into());
        } else if s.len() > Self::max_len_with_key(k) {
            return Err("string length exceeds maximum length".into());
        }

        // Trivial-encrypt characters.
        let mut chars = s
            .chars()
            .map(|c| {
                let ct = k.k.create_trivial_radix(c as u8, k.num_blocks_char);
                FheAsciiChar(ct)
            })
            .collect::<Vec<_>>();

        // Append terminating character.
        let term = Self::term_char(k);
        chars.push(term);

        Ok(FheString(chars))
    }

    pub fn decrypt(&self, k: &ClientKey) -> String {
        let chars = self
            .0
            .iter()
            .map(|c| k.k.decrypt::<u8>(&c.0))
            .filter(|&c| c != 0u8)
            .collect::<Vec<_>>();
        String::from_utf8(chars).unwrap()
    }

    /// Returns the length of `self`.
    pub fn len(&self, k: &ServerKey) -> FheUsize {
        // l = sum_{i in 1..self.len} (self[i-1] != 0 && self[i] == 0) * i
        let v = self
            .0
            .par_windows(2)
            .enumerate()
            .map(|(i_sub_1, pair)| {
                log::trace!("len: at index {i_sub_1}");
                let self_isub1 = &pair[0];
                let self_i = &pair[1];
                let self_isub1_neq_0 = k.k.scalar_ne_parallelized(&self_isub1.0, Self::TERMINATOR);
                let self_i_eq_0 = k.k.scalar_eq_parallelized(&self_i.0, Self::TERMINATOR);
                let b = k.k.boolean_bitand(&self_isub1_neq_0, &self_i_eq_0);
                let i = i_sub_1 + 1;
                let i_radix = FheUsize::new_trivial(k, i);
                if_then_else_zero(k, &b, &i_radix)
            })
            .collect::<Vec<_>>();

        let l = k.k.unchecked_sum_ciphertexts_vec_parallelized(v);
        match l {
            Some(l) => l,
            None => FheUsize::new_trivial(k, 0),
        }
    }

    /// Returns an upper bound on the length of `self`.
    pub fn max_len(&self) -> usize {
        // Substract 1 because strings are 0-terminated.
        self.0.len() - 1
    }

    /// Returns `self[..index]`.
    pub fn substr_to(&self, k: &ServerKey, index: &FheUsize) -> FheString {
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(i, ai)| {
                log::trace!("substr_to: at index {i}");

                // a[i] = i < index ? a[i] : 0
                let i_lt_index = k.k.scalar_gt_parallelized(index, i as u64);
                let ai = if_then_else_zero(k, &i_lt_index, &ai.0);
                FheAsciiChar(ai)
            })
            .collect();
        FheString(v)
    }

    /// Returns `self[index..]`.
    pub fn substr_from(&self, k: &ServerKey, index: &FheUsize) -> FheString {
        let v = (0..self.0.len())
            .into_par_iter()
            .map(|i| {
                log::trace!("substr_from: at index {i}");

                // a[i] = a[i + index]
                let i_add_index = k.k.scalar_add_parallelized(index, i as u64);
                self.char_at(k, &i_add_index)
            })
            .collect();
        FheString(v)
    }

    /// Returns `self[start..end]`.
    pub fn substr_end(&self, k: &ServerKey, start: &FheUsize, end: &FheUsize) -> FheString {
        let v = (0..self.0.len())
            .into_par_iter()
            .map(|i| {
                log::trace!("substr_end: at index {i}");

                // a[i] = i + index < end ? a[i + index] : 0
                let i_add_index = k.k.scalar_add_parallelized(start, i as u64);
                let i_add_index_lt_end = k.k.lt_parallelized(&i_add_index, end);
                let self_i_add_index = self.char_at(k, &i_add_index);
                let ai = if_then_else_zero(k, &i_add_index_lt_end, &self_i_add_index.0);
                FheAsciiChar(ai)
            })
            .collect();
        FheString(v)
    }

    /// Returns the character at the given index. Returns 0 if the index is out
    /// of bounds.
    pub fn char_at(&self, k: &ServerKey, i: &FheUsize) -> FheAsciiChar {
        // ai = i == 0 ? a[0] : 0 + ... + i == n ? a[n] : 0
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(j, aj)| {
                log::trace!("char_at: at index {j}");

                // i == j ? a[j] : 0
                let i_eq_j = k.k.scalar_eq_parallelized(i, j as u64);
                if_then_else_zero(k, &i_eq_j, &aj.0)
            })
            .collect::<Vec<_>>();

        let ai = k.k.unchecked_sum_ciphertexts_vec_parallelized(v);
        match ai {
            Some(c) => FheAsciiChar(c),
            None => Self::term_char(k),
        }
    }

    /// Returns the maximum length of an FheString when using key `k`.
    pub fn max_len_with_key<K: Key>(k: &K) -> usize {
        // We can only handle strings for which the length can be represented by
        // an FheUsize.
        FheUsize::max(k)
    }

    /// Returns a copy of `self` padded so that it can hold `l` characters.
    ///
    /// # Panics
    /// Panics if l exceeds the maximum length.
    fn pad(&self, k: &ServerKey, l: usize) -> Self {
        if l > Self::max_len_with_key(k) {
            panic!("pad length exceeds maximum length")
        } else if l < self.max_len() {
            // Nothing to pad.
            return self.clone();
        }

        let mut v = self.0.to_vec();
        let term = Self::term_char(k);
        // l + 1 because of termination character.
        (0..l + 1 - self.0.len()).for_each(|_| v.push(term.clone()));
        FheString(v)
    }

    fn term_char(k: &ServerKey) -> FheAsciiChar {
        FheAsciiChar(k.k.create_trivial_radix(Self::TERMINATOR, k.num_blocks_char))
    }
}

/// Given `v` and `Enc(i)`, return `v[i]`. Returns `0` if `i` is out of bounds.
pub fn element_at_bool(k: &ServerKey, v: &[BooleanBlock], i: &FheUsize) -> BooleanBlock {
    // ai = i == 0 ? a[0] : 0 + ... + i == n ? a[n] : 0
    let v = v
        .par_iter()
        .enumerate()
        .map(|(j, aj)| {
            log::trace!("element_at: at index {j}");

            // i == j ? a[j] : 0
            let i_eq_j = k.k.scalar_eq_parallelized(i, j as u64);

            k.k.boolean_bitand(&i_eq_j, aj)
        })
        .collect::<Vec<_>>();

    any(k, &v)
}

/// Searches `v` for the first index `i` with `p(v[i]) == 1`.
///
/// Expects that `p` returns an encryption of either 0 or 1.
pub fn index_of_unchecked<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> BooleanBlock,
) -> FheOption<FheUsize> {
    index_of_unchecked_with_options(k, v, p, false)
}

/// Searches `v` for the last index `i` with `p(v[i]) == 1`.
///
/// Expects that `p` returns an encryption of either 0 or 1.
pub fn rindex_of_unchecked<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> BooleanBlock,
) -> FheOption<FheUsize> {
    index_of_unchecked_with_options(k, v, p, true)
}

/// Searches `v` for the first index `i` with `p(v[i]) == 1`. If `reverse`,
/// searches in reverse direction.
///
/// Expects that `p` returns an encryption of either 0 or 1.
fn index_of_unchecked_with_options<T: Sync>(
    k: &ServerKey,
    v: &[T],
    p: fn(&ServerKey, &T) -> BooleanBlock,
    reverse: bool,
) -> FheOption<FheUsize> {
    let mut b = k.k.create_trivial_boolean_block(false); // Pattern contained.
    let mut index = FheUsize::new_trivial(k, 0); // Pattern index.

    let items: Vec<_> = if reverse {
        v.iter().enumerate().rev().collect()
    } else {
        v.iter().enumerate().collect()
    };

    // Evaluate predicate `p` on each element of `v`.
    let p_eval: Vec<_> = items
        .par_iter()
        .map(|(i, x)| {
            let pi = p(k, x);
            let pi_mul_i = scalar_if_then_else_zero(k, &pi, *i as u64);
            (i, pi, pi_mul_i)
        })
        .collect();

    // Find first index for which predicate evaluated to 1.
    p_eval.into_iter().for_each(|(i, pi, pi_mul_i)| {
        log::trace!("index_of_opt_unchecked: at index {i}");

        // index = b ? index : (pi ? i : 0)
        index = k.k.if_then_else_parallelized(&b, &index, &pi_mul_i);

        // b = b || pi
        b = k.k.boolean_bitor(&b, &pi);
    });

    FheOption {
        is_some: b,
        val: index,
    }
}

/// FheOption represents an encrypted option type.
pub struct FheOption<T> {
    /// Whether this option decrypts to `Some` or `None`.
    pub is_some: BooleanBlock,
    /// The optional value.
    pub val: T,
}

impl FheOption<RadixCiphertext> {
    pub fn decrypt(&self, k: &ClientKey) -> Option<u64> {
        let is_some = k.k.decrypt_bool(&self.is_some);
        match is_some {
            true => {
                let val = k.decrypt::<u64>(&self.val);
                Some(val)
            }
            false => None,
        }
    }
}

impl FheOption<FheUsize> {
    pub fn decrypt(&self, k: &ClientKey) -> Option<usize> {
        let is_some = k.k.decrypt_bool(&self.is_some);
        match is_some {
            true => Some(k.decrypt_usize(&self.val)),
            false => None,
        }
    }
}

impl FheOption<FheString> {
    pub fn decrypt(&self, k: &ClientKey) -> Option<String> {
        let is_some = k.k.decrypt_bool(&self.is_some);
        match is_some {
            true => {
                let val = self.val.decrypt(k);
                Some(val)
            }
            false => None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheUsize(pub(crate) RadixCiphertext);

impl FheUsize {
    /// Creates a new encrypted usize with value `v`.
    pub fn new(k: &ClientKey, v: usize) -> Self {
        let c = k.k.encrypt(v as u64);
        let num_blocks = c.blocks().len();
        match num_blocks.cmp(&k.num_blocks_usize) {
            cmp::Ordering::Less => {
                let sk = IntegerServerKey::new_radix_server_key(&k.k);
                let c = sk
                    .extend_radix_with_trivial_zero_blocks_msb(&c, k.num_blocks_usize - num_blocks);
                FheUsize(c)
            }
            cmp::Ordering::Equal => FheUsize(c),
            cmp::Ordering::Greater => {
                let sk = IntegerServerKey::new_radix_server_key(&k.k);
                let c = sk.trim_radix_blocks_msb(&c, num_blocks - k.num_blocks_usize);
                FheUsize(c)
            }
        }
    }

    /// Creates a new trivial usize ciphertext with value `v`.
    pub fn new_trivial(k: &ServerKey, v: usize) -> FheUsize {
        Self(k.k.create_trivial_radix(v as u64, k.num_blocks_usize))
    }

    /// Creates a new trivial usize ciphertext with value `b ? 1 : 0`.
    pub fn new_from_bool(k: &ServerKey, b: &BooleanBlock) -> FheUsize {
        Self(b.clone().into_radix(k.num_blocks_usize, &k.k))
    }

    pub fn max<K: Key>(k: &K) -> usize {
        k.msg_mod().pow(k.num_blocks_usize() as u32) - 1
    }

    pub fn decrypt(&self, k: &ClientKey) -> usize {
        k.k.decrypt::<u64>(&self.0) as usize
    }
}

impl IntegerRadixCiphertext for FheUsize {
    const IS_SIGNED: bool = false;

    fn into_blocks(self) -> Vec<tfhe::shortint::prelude::Ciphertext> {
        self.0.into_blocks()
    }
}

impl IntegerCiphertext for FheUsize {
    fn blocks(&self) -> &[tfhe::shortint::prelude::Ciphertext] {
        self.0.blocks()
    }

    fn from_blocks(blocks: Vec<tfhe::shortint::prelude::Ciphertext>) -> Self {
        let c = RadixCiphertext::from_blocks(blocks);
        Self(c)
    }

    fn blocks_mut(&mut self) -> &mut [tfhe::shortint::prelude::Ciphertext] {
        self.0.blocks_mut()
    }
}

impl From<Vec<tfhe::shortint::Ciphertext>> for FheUsize {
    fn from(value: Vec<tfhe::shortint::Ciphertext>) -> Self {
        let c = RadixCiphertext::from(value);
        Self(c)
    }
}
