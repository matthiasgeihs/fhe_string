//! Functionality for string replacement.

use tfhe::integer::IntegerCiphertext;

use crate::{
    ciphertext::{
        element_at_bool,
        logic::{if_then_else_bool, if_then_else_zero},
    },
    server_key::ServerKey,
};

use super::{FheAsciiChar, FheString, FheUsize};

impl FheString {
    /// Returns `self` where `p` is replaced by `s` up to length `l`.
    pub fn replace(&self, k: &ServerKey, p: &FheString, s: &FheString, l: usize) -> FheString {
        self.replace_opt(k, p, s, None, l)
    }

    /// Returns `self` where `p` is replaced by `s` up to `n_max` times and the
    /// output has maximum length `l`.
    pub fn replacen(
        &self,
        k: &ServerKey,
        p: &FheString,
        s: &FheString,
        n_max: &FheUsize,
        l: usize,
    ) -> FheString {
        self.replace_opt(k, p, s, Some(n_max), l)
    }

    /// Returns `self` where `p` is replaced by `s` up to `n_max` times and the
    /// output has maximum length `l`. If `n_max` is None, then there is no
    /// limit on the number of replacements.
    fn replace_opt(
        &self,
        k: &ServerKey,
        p: &FheString,
        s: &FheString,
        n_max: Option<&FheUsize>,
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
        let mut in_match = k.k.create_trivial_boolean_block(false);
        let mut j = FheUsize::new_trivial(k, 0);
        let mut n = FheUsize::new_trivial(k, 0);
        let mut v = Vec::<FheAsciiChar>::new();
        (0..l).for_each(|i| {
            log::trace!("replace_nopt: at index {i}");

            // c = i + n * len_diff
            let n_mul_lendiff = k.k.mul_parallelized(&n, &len_diff);
            let c = k.k.scalar_add_parallelized(&n_mul_lendiff, i as u64);

            let j_lt_slen = k.k.lt_parallelized(&j, &s_len);
            let match_and_jltslen = k.k.boolean_bitand(&in_match, &j_lt_slen);

            let found_c = element_at_bool(k, &found, &c);
            let foundc_and_n_lt_nmax = match n_max {
                Some(n_max) => {
                    let n_lt_nmax = k.k.lt_parallelized(&n, n_max);
                    k.k.boolean_bitand(&found_c, &n_lt_nmax)
                }
                None => found_c,
            };
            let foundc_and_n_lt_nmax_radix = foundc_and_n_lt_nmax
                .clone()
                .into_radix(n.blocks().len(), &k.k);
            let n_add_found_c = k.k.add_parallelized(&n, &foundc_and_n_lt_nmax_radix);

            in_match = if_then_else_bool(k, &match_and_jltslen, &in_match, &foundc_and_n_lt_nmax);
            j = if_then_else_zero(k, &match_and_jltslen, &j);
            n =
                k.k.if_then_else_parallelized(&match_and_jltslen, &n, &n_add_found_c);

            let sj = s.char_at(k, &j).0;
            let self_c = self.char_at(k, &c).0;
            let vi = k.k.if_then_else_parallelized(&in_match, &sj, &self_c);
            v.push(FheAsciiChar(vi));

            j = k.k.scalar_add_parallelized(&j, 1u8);
        });

        // Append 0 to terminate string.
        v.push(Self::term_char(k));
        FheString(v)
    }
}
