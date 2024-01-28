//! Functionality for string splitting.

use rayon::prelude::*;
use tfhe::integer::{IntegerCiphertext, RadixCiphertext};

use crate::{ciphertext::element_at_bool, client_key::ClientKey, server_key::ServerKey};

use super::{FheAsciiChar, FheOption, FheString, Uint};

/// An element of an `FheStringSliceVector`.
#[derive(Clone)]
struct FheStringSlice {
    /// The start index of the string slice.
    start: RadixCiphertext,

    /// The end index of the string slice, exclusive.
    end: RadixCiphertext,
}

/// An encrypted vector of substrings of an encrypted reference string.
pub struct FheStringSliceVector {
    /// The reference string.
    s: FheString,

    /// The vector of substrings. Since we can't always know the real length of
    /// a vector, we use optional elements. `None` elements are skipped.
    v: Vec<FheOption<FheStringSlice>>,
}

impl FheStringSliceVector {
    /// Returns the number of substrings contained in this vector.
    pub fn len(&self, k: &ServerKey) -> RadixCiphertext {
        let v = self
            .v
            .par_iter()
            .map(|vi| vi.is_some.clone().into_radix(k.num_blocks, &k.k))
            .collect::<Vec<_>>();
        k.k.unchecked_sum_ciphertexts_vec_parallelized(v)
            .unwrap_or(k.create_zero())
    }

    /// Returns the substring stored at index `i`, if existent.
    pub fn get(&self, k: &ServerKey, i: &RadixCiphertext) -> FheOption<FheString> {
        let mut n = k.create_zero();

        let init = FheOption {
            is_some: k.k.create_trivial_boolean_block(false),
            val: FheStringSlice {
                start: k.create_zero(),
                end: k.create_zero(),
            },
        };

        let slice = self.v.iter().enumerate().fold(init, |acc, (j, vi)| {
            // acc = i == n && vi.is_some ? (j, vi.end) : acc
            let i_eq_n = k.k.eq_parallelized(i, &n);
            let is_some = k.k.boolean_bitand(&i_eq_n, &vi.is_some);
            let j_radix = k.create_value(j as Uint);
            let start =
                k.k.if_then_else_parallelized(&is_some, &j_radix, &acc.val.start);
            let end =
                k.k.if_then_else_parallelized(&is_some, &vi.val.end, &acc.val.end);
            let acc = FheOption {
                is_some,
                val: FheStringSlice { start, end },
            };

            // n += vi.is_some
            let is_some_radix = vi.is_some.clone().into_radix(n.blocks().len(), &k.k);
            k.k.add_assign_parallelized(&mut n, &is_some_radix);

            acc
        });

        let val = self.s.substr_end(k, &slice.val.start, &slice.val.end);
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

        self.v = self
            .v
            .iter()
            .map(|vi| {
                // is_some = n < i ? vi.is_some : 0
                let n_lt_i = k.k.lt_parallelized(&n, i);
                let is_some = k.k.boolean_bitand(&n_lt_i, &vi.is_some);

                // n += v[i].is_some
                let is_some_radix = vi.is_some.clone().into_radix(n.blocks().len(), &k.k);
                k.k.add_assign_parallelized(&mut n, &is_some_radix);

                FheOption {
                    is_some,
                    val: vi.val.clone(),
                }
            })
            .collect::<Vec<_>>();
    }

    /// Truncate the last element if it is empty.
    fn truncate_last_if_empty(&mut self, k: &ServerKey) {
        let mut b = k.k.create_trivial_boolean_block(true);
        let mut v = self
            .v
            .iter()
            .rev()
            .map(|vi| {
                // is_empty = vi.start >= vi.end
                let is_empty = k.k.ge_parallelized(&vi.val.start, &vi.val.end);

                // is_some = b && vi.is_some && is_empty ? 0 : vi.is_some
                let b_and_start = k.k.boolean_bitand(&b, &vi.is_some);
                let b_and_start_and_empty = k.k.boolean_bitand(&b_and_start, &is_empty);
                let not_b_and_start_and_empty = k.k.boolean_bitnot(&b_and_start_and_empty);
                let is_some = k.k.boolean_bitand(&not_b_and_start_and_empty, &vi.is_some);

                // b = b && !vi.is_some
                let not_start = k.k.boolean_bitnot(&vi.is_some);
                b = k.k.boolean_bitand(&b, &not_start);

                FheOption {
                    is_some,
                    val: vi.val.clone(),
                }
            })
            .collect::<Vec<_>>();
        v.reverse();
        self.v = v;
    }

    /// Expand the first slice to the beginning of the string.
    fn expand_first(&mut self, k: &ServerKey) {
        // Find the first item and set its start point to 0.
        let mut not_found = k.k.create_trivial_boolean_block(true);
        let zero = k.create_zero();
        self.v = self
            .v
            .iter()
            .map(|vi| {
                // start = not_found && vi.is_some ? 0 : vi.start
                let not_found_and_some = k.k.boolean_bitand(&not_found, &vi.is_some);
                let start =
                    k.k.if_then_else_parallelized(&not_found_and_some, &zero, &vi.val.start);

                // not_found = not_found && !vi.is_some
                let not_some = k.k.boolean_bitnot(&vi.is_some);
                not_found = k.k.boolean_bitand(&not_found, &not_some);

                FheOption {
                    is_some: vi.is_some.clone(),
                    val: FheStringSlice {
                        start,
                        end: vi.val.end.clone(),
                    },
                }
            })
            .collect::<Vec<_>>();
    }

    /// Expand the last slice to the end of the string.
    fn expand_last(&mut self, k: &ServerKey) {
        // Find the last item and set its end point to s.len.
        let mut not_found = k.k.create_trivial_boolean_block(true);
        let self_len = self.s.len(k);
        let mut v = self
            .v
            .iter()
            .rev()
            .map(|vi| {
                // end = not_found && vi.is_some ? self.s.len : vi.end
                let not_found_and_some = k.k.boolean_bitand(&not_found, &vi.is_some);
                let end =
                    k.k.if_then_else_parallelized(&not_found_and_some, &self_len, &vi.val.end);

                // not_found = not_found && !vi.is_some
                let not_some = k.k.boolean_bitnot(&vi.is_some);
                not_found = k.k.boolean_bitand(&not_found, &not_some);

                FheOption {
                    is_some: vi.is_some.clone(),
                    val: FheStringSlice {
                        start: vi.val.start.clone(),
                        end,
                    },
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
            .filter_map(|vi| {
                let is_some = k.0.decrypt_bool(&vi.is_some);
                match is_some {
                    false => None,
                    true => {
                        let start = k.0.decrypt::<Uint>(&vi.val.start) as usize;
                        let end = k.0.decrypt::<Uint>(&vi.val.end) as usize;
                        let slice = s_dec.get(start..end).unwrap_or_default();
                        log::trace!("decrypt slice: [{start}, {end}]");
                        Some(slice.to_string())
                    }
                }
            })
            .collect::<Vec<_>>()
    }

    /// Reverses the order of the elements.
    pub fn reverse(&mut self) {
        self.v.reverse();
    }
}

impl FheString {
    /// Splits `self` at each occurrence of `p` into a vector of substrings. If
    /// `inclusive`, then the pattern is included at the end of each substring.
    /// If `reverse`, then the string is searched in reverse direction.
    fn split_opt(
        &self,
        k: &ServerKey,
        p: &FheString,
        inclusive: bool,
        reverse: bool,
    ) -> FheStringSliceVector {
        /*
        matches = s.find_all_non_overlapping(k, p);
        n = s.max_len + 2
        next_match = s.len
        let substrings = (0..n).rev().map(|i| {
            next_match = matches[i] ? i + (inclusive ? p.len : 0) : next_match
            (
                is_some: i == 0 || matches[i - p.len] || i > s.len + 2,
                start: max(i - p.empty, 0),
                end: next_match,
            )
        })
         */

        let pattern_empty = p.is_empty(k);
        let mut matches = if reverse {
            self.rfind_all_non_overlapping(k, p)
        } else {
            self.find_all_non_overlapping(k, p)
        };
        matches.push(pattern_empty.clone());
        matches.push(pattern_empty.clone());

        let p_len = p.len(k);
        let self_len = self.len(k);

        let n = self.max_len() + 2; // Maximum number of entries.
        let n_hidden = k.k.scalar_add_parallelized(&self_len, 2 as Uint); // Better bound based on hidden length.
        let mut next_match = self_len.clone();
        let mut elems = (0..n)
            .rev()
            .map(|i| {
                log::trace!("split_opt: at index {i}");

                // is_some_i = i == 0 || matches[i - p.len] && i < self.len + 2
                let is_some = if i == 0 {
                    k.k.create_trivial_boolean_block(true)
                } else {
                    let i_radix = k.create_value(i as Uint);
                    let i_sub_plen = k.k.sub_parallelized(&i_radix, &p_len);
                    let mi = element_at_bool(k, &matches, &i_sub_plen);
                    let i_lt_n_hidden = k.k.scalar_gt_parallelized(&n_hidden, i as Uint);
                    k.k.boolean_bitand(&i_lt_n_hidden, &mi)
                };

                // next_match_target = i + (inclusive ? p.len : 0)
                let next_match_target = if inclusive {
                    k.k.scalar_add_parallelized(&p_len, i as Uint)
                } else {
                    k.create_value(i as Uint)
                };

                // next_match[i] = matches[i] ? next_match_target : next_match[i+1]
                let false_block = k.k.create_trivial_boolean_block(false);
                let matches_i = matches.get(i).unwrap_or(&false_block);
                next_match =
                    k.k.if_then_else_parallelized(matches_i, &next_match_target, &next_match);

                // start = max(i - p.empty, 0)
                let start = if i > 0 {
                    let pattern_empty_radix = pattern_empty.clone().into_radix(k.num_blocks, &k.k);
                    k.k.sub_parallelized(&k.create_value(i as Uint), &pattern_empty_radix)
                } else {
                    k.create_zero()
                };

                FheOption {
                    is_some,
                    val: FheStringSlice {
                        start,
                        end: next_match.clone(),
                    },
                }
            })
            .collect::<Vec<_>>();
        elems.reverse();

        let mut v = FheStringSliceVector {
            s: self.clone(),
            v: elems,
        };

        // If inclusive, remove last element if empty.
        if inclusive {
            v.truncate_last_if_empty(k);
        }

        v
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn split(&self, k: &ServerKey, p: &FheString) -> FheStringSliceVector {
        self.split_opt(k, p, false, false)
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings and
    /// returns the elements in reverse order.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn rsplit(&self, k: &ServerKey, p: &FheString) -> FheStringSliceVector {
        let mut v = self.split_opt(k, p, false, true);
        v.reverse();
        v
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings
    /// where the pattern is included at the end of each substring.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn split_inclusive(&self, k: &ServerKey, p: &FheString) -> FheStringSliceVector {
        self.split_opt(k, p, true, false)
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings of
    /// at most length `n`.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn splitn(
        &self,
        k: &ServerKey,
        n: &RadixCiphertext,
        p: &FheString,
    ) -> FheStringSliceVector {
        let mut v = self.split(k, p);
        v.truncate(k, n);
        v.expand_last(k);
        v
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings of
    /// at most length `n` in reverse order.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn rsplitn(
        &self,
        k: &ServerKey,
        n: &RadixCiphertext,
        p: &FheString,
    ) -> FheStringSliceVector {
        let mut v = self.rsplit(k, p);
        v.truncate(k, n);
        v.reverse();
        v.expand_first(k);
        v.reverse();
        v
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings
    /// where the last substring is skipped if empty.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn split_terminator(&self, k: &ServerKey, p: &FheString) -> FheStringSliceVector {
        let mut v = self.split(k, p);
        v.truncate_last_if_empty(k);
        v
    }

    /// Splits `self` at each occurrence of `p` into a vector of substrings in
    /// reverse order where the last substring is skipped if empty.
    ///
    /// # Limitations
    /// If p.len == 0, the result is undefined.
    pub fn rsplit_terminator(&self, k: &ServerKey, p: &FheString) -> FheStringSliceVector {
        let mut v = self.rsplit(k, p);
        v.reverse();
        v.truncate_last_if_empty(k);
        v.reverse();
        v
    }

    /// Splits `self` at each occurrence of ascii whitespace into a vector of
    /// substrings.
    pub fn split_ascii_whitespace(&self, k: &ServerKey) -> FheStringSliceVector {
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
            k.k.boolean_bitor(&w, &z)
        };
        let whitespace = self.find_all_pred_unchecked(k, is_whitespace);
        let next_whitespace = self.find_all_next_pred_unchecked(k, is_whitespace);

        let zero = k.create_zero();
        let opt_default = FheOption {
            is_some: k.k.create_trivial_boolean_block(false),
            val: zero.clone(),
        };

        let self_len = self.len(k);
        let v = self
            .0
            .par_iter()
            .enumerate()
            .map(|(i, _)| {
                // is_some = !whitespace[i] && (i == 0 || whitespace[i-1]);
                let not_whitespace = k.k.boolean_bitnot(&whitespace[i]);
                let i_eq_0_or_prev_whitespace = if i == 0 {
                    k.k.create_trivial_boolean_block(true)
                } else {
                    whitespace[i - 1].clone()
                };
                let is_some =
                    k.k.boolean_bitand(&not_whitespace, &i_eq_0_or_prev_whitespace);

                // end = s.index_of_next_white_space_or_max_len(i+1);
                let index_of_next = next_whitespace.get(i + 1).unwrap_or(&opt_default);
                let end = k.k.if_then_else_parallelized(
                    &index_of_next.is_some,
                    &index_of_next.val,
                    &self_len,
                );

                FheOption {
                    is_some,
                    val: FheStringSlice {
                        start: k.create_value(i as Uint),
                        end,
                    },
                }
            })
            .collect::<Vec<_>>();

        FheStringSliceVector { s: self.clone(), v }
    }

    /// Splits `self` on the first occurrence of the specified delimiter and
    /// returns prefix before delimiter and suffix after delimiter. Optionally,
    /// searches in reverse order.
    fn split_once_opt(
        &self,
        k: &ServerKey,
        p: &FheString,
        reverse: bool,
    ) -> FheOption<(FheString, FheString)> {
        let found = if reverse {
            self.rfind(k, p)
        } else {
            self.find(k, p)
        };
        let p_len = p.len(k);
        let next = k.k.add_parallelized(&found.val, &p_len);

        // s1 = s[..found.val]
        // s1 = s[found.val+p.len..]
        let s1 = self.substr_to(k, &found.val);
        let s2 = self.substr_from(k, &next);

        FheOption {
            is_some: found.is_some,
            val: (s1, s2),
        }
    }

    /// Splits `self` on the first occurrence of the specified delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    pub fn split_once(&self, k: &ServerKey, p: &FheString) -> FheOption<(FheString, FheString)> {
        self.split_once_opt(k, p, false)
    }

    /// Splits `self` on the last occurrence of the specified delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    pub fn rsplit_once(&self, k: &ServerKey, p: &FheString) -> FheOption<(FheString, FheString)> {
        self.split_once_opt(k, p, true)
    }
}
