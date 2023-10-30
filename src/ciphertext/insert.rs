use tfhe::integer::RadixCiphertext;

use rayon::prelude::*;

use crate::{
    ciphertext::{binary_if_then_else, FheAsciiChar, Uint},
    server_key::ServerKey,
};

use super::FheString;

impl FheString {
    /// Returns `self + s`.
    pub fn add(&self, k: &ServerKey, s: &FheString) -> FheString {
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

    /// Returns a copy of `self` where `s` is inserted at the given index.
    ///
    /// # Panics
    /// Panics on index out of bounds.
    pub fn insert(&self, k: &ServerKey, index: &RadixCiphertext, s: &FheString) -> FheString {
        let a = self;
        let b = s;
        let l = std::cmp::min(a.max_len() + b.max_len(), Self::max_len_with_key(k));
        let b_len = b.len(k);

        let mut v = (0..l)
            .into_par_iter()
            .map(|i| {
                // v[i] = i < index ? a[i] : (i < index + b.len ? b[i - index] : a[i - b.len])

                // c0 = i < index
                let c0 = k.k.scalar_gt_parallelized(index, i as Uint);

                // c1 = a[i]
                let c1 = &a.0[i % a.0.len()].0;

                // b[i - index]
                let i_radix = k.create_value(i as Uint);
                let i_sub_index = k.k.sub_parallelized(&i_radix, &index);
                let b_i_sub_index = b.char_at(k, &i_sub_index);

                // a[i - b.len]
                let i_sub_b_len = k.k.sub_parallelized(&i_radix, &b_len);
                let a_i_sub_b_len = a.char_at(k, &i_sub_b_len);

                // c2 = i < index + b.len ? b[i - index] : a[i - b.len]
                let index_add_blen = k.k.add_parallelized(index, &b_len);
                let i_lt_index_add_blen = k.k.scalar_gt_parallelized(&index_add_blen, i as Uint);
                let c2 = binary_if_then_else(
                    k,
                    &i_lt_index_add_blen,
                    &b_i_sub_index.0,
                    &a_i_sub_b_len.0,
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
}
