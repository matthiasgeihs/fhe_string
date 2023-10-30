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
        let zero = FheAsciiChar(k.create_zero());
        // l + 1 because of termination character.
        (0..l + 1 - self.0.len()).for_each(|_| v.push(zero.clone()));
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

    // Indicates whether elements are indexed in reverse order.
    reverse: bool,
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

    /// Returns the substring stored at index `i`, if existent.
    pub fn get(&self, k: &ServerKey, i: &RadixCiphertext) -> FheOption<FheString> {
        let mut n = k.create_zero();

        let init = FheOption {
            is_some: k.create_zero(),
            val: FheStringSlice {
                is_start: k.create_zero(), // This will hold the starting index.
                end: k.create_zero(),
            },
        };

        let mut iter_items = self.v.iter().enumerate().collect::<Vec<_>>();
        if self.reverse {
            iter_items.reverse()
        }
        let slice = iter_items.iter().fold(init, |acc, (j, vi)| {
            // acc = i == n && vi.is_start ? (j, vi.end) : acc
            let i_eq_n = k.k.eq_parallelized(i, &n);
            let is_some = binary_and(k, &i_eq_n, &vi.is_start);
            let j_radix = k.create_value(*j as Uint);
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

        let val = self.s.substr_end(k, &slice.val.is_start, &slice.val.end);
        FheOption {
            is_some: slice.is_some,
            val,
        }
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

        let iter_items = self.v.iter();
        let iter_items = if self.reverse {
            iter_items.rev().collect::<Vec<_>>()
        } else {
            iter_items.collect::<Vec<_>>()
        };

        self.v = iter_items
            .iter()
            .map(|vi| {
                // is_start = n < i ? vi.is_start : 0
                let n_lt_i = k.k.lt_parallelized(&n, &i);
                let is_start = binary_if_then_else(k, &n_lt_i, &vi.is_start, &zero);

                // n += v[i].is_start
                k.k.add_assign_parallelized(&mut n, &vi.is_start);

                FheStringSlice {
                    is_start,
                    end: vi.end.clone(),
                }
            })
            .collect::<Vec<_>>();

        if self.reverse {
            self.v.reverse();
        }
    }

    /// Truncate the last element if it is empty.
    fn truncate_last_if_empty(&mut self, k: &ServerKey) {
        let s_len = self.s.len(k);
        let mut b = k.create_one();

        let iter_items = self.v.iter().enumerate();
        let iter_items = if self.reverse {
            iter_items.collect::<Vec<_>>()
        } else {
            iter_items.rev().collect::<Vec<_>>()
        };

        let mut v = iter_items
            .iter()
            .map(|(i, vi)| {
                log::debug!("truncate_last_if_empty: i = {}", i);

                // is_empty = vi.end <= i || s.len <= i
                let end_le_i = k.k.scalar_le_parallelized(&vi.end, *i as Uint);
                let slen_le_i = k.k.scalar_le_parallelized(&s_len, *i as Uint);
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
        if !self.reverse {
            v.reverse();
        }
        self.v = v;
    }

    /// Expand the last slice to the end of the string.
    fn expand_last(&mut self, k: &ServerKey) {
        self.v = if self.reverse {
            // Find the first encrypted item, store its end point, and disable
            // it. Enable the first cleartext item and set its end point to the
            // stored end point.
            let mut not_found = k.create_one();
            let mut end = k.create_value(self.s.max_len() as Uint);
            let zero = k.create_zero();
            let mut v = self
                .v
                .iter()
                .map(|vi| {
                    // is_start = not_found && vi.is_start ? 0 : vi.is_start
                    let not_found_and_start = binary_and(k, &not_found, &vi.is_start);
                    let is_start =
                        binary_if_then_else(k, &not_found_and_start, &zero, &vi.is_start);
                    end = binary_if_then_else(k, &not_found_and_start, &vi.end, &end);

                    // not_found = not_found && !vi.is_start
                    let not_start = binary_not(k, &vi.is_start);
                    not_found = binary_and(k, &not_found, &not_start);

                    FheStringSlice {
                        is_start,
                        end: vi.end.clone(),
                    }
                })
                .collect::<Vec<_>>();
            if let Some(v0) = v.get_mut(0) {
                v0.is_start = k.create_one();
                v0.end = end;
            }
            v
        } else {
            // Find the last item and set its end point to s.max_len.
            let mut not_found = k.create_one();
            let mut v = self
                .v
                .iter()
                .rev()
                .map(|vi| {
                    // end = not_found && vi.is_start ? self.s.max_len : vi.end
                    let not_found_and_start = binary_and(k, &not_found, &vi.is_start);
                    let max_len = k.create_value(self.s.max_len() as Uint);
                    let end = binary_if_then_else(k, &not_found_and_start, &max_len, &vi.end);

                    // not_found = not_found && !vi.is_start
                    let not_start = binary_not(k, &vi.is_start);
                    not_found = binary_and(k, &not_found, &not_start);

                    FheStringSlice {
                        is_start: vi.is_start.clone(),
                        end,
                    }
                })
                .collect::<Vec<_>>();
            v.reverse();
            v
        };
    }

    /// Decrypts this vector.
    pub fn decrypt(&self, k: &ClientKey) -> Vec<String> {
        let s_dec = self.s.decrypt(k);
        let mut v = self
            .v
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
            .collect::<Vec<_>>();
        if self.reverse {
            v.reverse();
        }
        v
    }

    /// Reverses the order of the elements.
    pub fn reverse(&mut self) {
        self.reverse = !self.reverse;
    }
}

pub struct FheOption<T> {
    pub is_some: RadixCiphertext,
    pub val: T,
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings.
/// If `inclusive`, then the pattern is included at the end of each substring.
/// If `reverse`, then the string is searched in reverse direction.
fn split_opt(
    k: &ServerKey,
    s: &FheString,
    p: &FheString,
    inclusive: bool,
    reverse: bool,
) -> FheStringSliceVector {
    /*
    matches = s.find_all_non_overlapping(k, p);
    n = s.max_len + 1
    next_match = s.max_len
    let substrings = (0..n).rev().map(|i| {
        is_start_i = i == 0 || matches[i - p.len]
        next_match = matches[i] ? i + (inclusive ? p.len : 0) : next_match
        end_i = next_match
    })
     */

    let matches = if reverse {
        s.rfind_all_non_overlapping(k, p)
    } else {
        s.find_all_non_overlapping(k, p)
    };
    let p_len = p.len(k);

    let n = s.max_len() + 1; // Maximum number of entries.
    let mut next_match = k.create_value(s.max_len() as Uint);
    let zero = k.create_zero();
    let mut elems = (0..n)
        .rev()
        .map(|i| {
            log::debug!("split_opt: at index {i}");

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
        reverse: false,
    };

    // If inclusive, remove last element if empty.
    if inclusive {
        v.truncate_last_if_empty(k);
    }

    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn split(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    split_opt(k, s, p, false, false)
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings and returns the elements in reverse order.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn rsplit(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    let mut v = split_opt(k, s, p, false, true);
    v.reverse();
    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// where the pattern is included at the end of each substring.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn split_inclusive(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    split_opt(k, s, p, true, false)
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// of at most length `n`.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
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
/// of at most length `n` in reverse order.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn rsplitn(
    k: &ServerKey,
    s: &FheString,
    n: &RadixCiphertext,
    p: &FheString,
) -> FheStringSliceVector {
    let mut v = rsplit(k, s, p);
    v.truncate(k, n);
    v.expand_last(k);
    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// where the last substring is skipped if empty.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn split_terminator(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    let mut v = split(k, s, p);
    v.truncate_last_if_empty(k);
    v
}

/// Splits the string `s` at each occurrence of `p` into a vector of substrings
/// in reverse order where the last substring is skipped if empty.
///
/// # Limitations
/// If p.len == 0, the result is undefined.
pub fn rsplit_terminator(k: &ServerKey, s: &FheString, p: &FheString) -> FheStringSliceVector {
    let mut v = rsplit(k, s, p);
    v.truncate_last_if_empty(k);
    v
}

/// Splits the string `s` at each occurrence of ascii whitespace into a vector
/// of substrings.
pub fn split_ascii_whitespace(k: &ServerKey, s: &FheString) -> FheStringSliceVector {
    /*
    whitespace = s.find_all_whitespace()
    v = s.0.map(|i, si| {
        is_start = !whitespace[i] && (i == 0 || whitespace[i-1]);
        end = s.index_of_next_white_space_or_max_len(i+1);
        (is_start, end)
    });
     */
    let is_whitespace = |k: &ServerKey, c: &FheAsciiChar| {
        let w = c.is_whitespace(k);
        // Also check for string termination character.
        let z = k.k.scalar_eq_parallelized(&c.0, FheString::TERMINATOR);
        binary_or(k, &w, &z)
    };
    let whitespace = s.find_all_pred_unchecked(k, is_whitespace);
    let next_whitespace = s.find_all_next_pred_unchecked(k, is_whitespace);

    let zero = k.create_zero();
    let opt_default = FheOption {
        is_some: zero.clone(),
        val: zero.clone(),
    };

    let v = s
        .0
        .par_iter()
        .enumerate()
        .map(|(i, _)| {
            // is_start = !whitespace[i] && (i == 0 || whitespace[i-1]);
            let not_whitespace = binary_not(k, &whitespace[i]);
            let i_eq_0_or_prev_whitespace = if i == 0 {
                k.create_one()
            } else {
                whitespace[i - 1].clone()
            };
            let is_start = binary_and(k, &not_whitespace, &i_eq_0_or_prev_whitespace);

            // end = s.index_of_next_white_space_or_max_len(i+1);
            let index_of_next = next_whitespace.get(i + 1).unwrap_or(&opt_default);
            let max_len = k.create_value(s.max_len() as Uint);
            let end = binary_if_then_else(k, &index_of_next.is_some, &index_of_next.val, &max_len);

            FheStringSlice { is_start, end }
        })
        .collect::<Vec<_>>();

    FheStringSliceVector {
        s: s.clone(),
        v,
        reverse: false,
    }
}

/// Splits the string on the first occurrence of the specified delimiter and
/// returns prefix before delimiter and suffix after delimiter. Optionally,
/// searches in reverse order.
fn split_once_opt(
    k: &ServerKey,
    s: &FheString,
    p: &FheString,
    reverse: bool,
) -> FheOption<FheStringSliceVector> {
    let found = if reverse { s.rfind(k, p) } else { s.find(k, p) };
    let max_len = s.max_len();
    let max_len_enc = k.create_value(max_len as Uint);
    let p_len = p.len(k);

    // next = found.val + p_len
    let next = k.k.add_parallelized(&found.val, &p_len);

    // v[i] = i == 0 ? (1, found.val) : (i == next ? 1 : 0, max_len)
    let v = (0..max_len + 1)
        .into_par_iter()
        .map(|i| match i {
            0 => FheStringSlice {
                is_start: k.create_one(),
                end: found.val.clone(),
            },
            _ => FheStringSlice {
                is_start: k.k.scalar_eq_parallelized(&next, i as Uint),
                end: max_len_enc.clone(),
            },
        })
        .collect();

    FheOption {
        is_some: found.is_some,
        val: FheStringSliceVector {
            s: s.clone(),
            v,
            reverse: false,
        },
    }
}

/// Splits the string on the first occurrence of the specified delimiter and
/// returns prefix before delimiter and suffix after delimiter.
pub fn split_once(k: &ServerKey, s: &FheString, p: &FheString) -> FheOption<FheStringSliceVector> {
    split_once_opt(k, s, p, false)
}

/// Splits the string on the last occurrence of the specified delimiter and
/// returns prefix before delimiter and suffix after delimiter.
pub fn rsplit_once(k: &ServerKey, s: &FheString, p: &FheString) -> FheOption<FheStringSliceVector> {
    split_once_opt(k, s, p, true)
}
