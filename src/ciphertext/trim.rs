use crate::server_key::ServerKey;

use super::{binary_and, binary_if_then_else, binary_not, FheOption, FheString};

impl FheString {
    /// Returns `self[i..]` where `i` is the index of the first non-whitespace
    /// character.
    pub fn trim_start(&self, k: &ServerKey) -> FheString {
        let i_opt = self.find_pred_unchecked(k, |k, c| {
            let is_whitespace = c.is_whitespace(k);
            binary_not(k, &is_whitespace)
        });

        let i = binary_if_then_else(k, &i_opt.is_some, &i_opt.val, &k.create_zero());
        self.substr(k, &i)
    }

    /// Returns `self[..i+1]` where `i` is the index of the last non-whitespace
    /// character.
    pub fn trim_end(&self, k: &ServerKey) -> FheString {
        let i_opt = self.rfind_pred_unchecked(k, |k, c| {
            // !is_terminator(c) && !is_whitespace(c)
            let is_term = k.k.scalar_eq_parallelized(&c.0, Self::TERMINATOR);
            let not_term = binary_not(k, &is_term);
            let is_whitespace = c.is_whitespace(k);
            let not_whitespace = binary_not(k, &is_whitespace);
            binary_and(k, &not_term, &not_whitespace)
        });

        // i = i_opt.is_some ? i_opt.val + 1 : 0
        let val_add_1 = k.k.scalar_add_parallelized(&i_opt.val, 1);
        let i = binary_if_then_else(k, &i_opt.is_some, &val_add_1, &k.create_zero());
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
    pub fn strip_prefix(&self, k: &ServerKey, s: &FheString) -> FheOption<FheString> {
        let b = self.substr_eq(k, 0, s);
        let index = s.len(k);
        let stripped = self.substr(k, &index);
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
        let is_some = binary_and(k, &found.is_some, &i_add_slen_eq_selflen);

        FheOption {
            is_some,
            val: stripped,
        }
    }
}
