//! Functionality for string conversion.

use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::server_key::ServerKey;

use super::{logic::binary_and, FheAsciiChar, FheString, Uint};

impl FheAsciiChar {
    const CASE_DIFF: Uint = 32;

    /// Returns whether `self` is uppercase.
    pub fn is_uppercase(&self, k: &ServerKey) -> RadixCiphertext {
        // (65 <= c <= 90)
        let c_geq_65 = k.k.scalar_ge_parallelized(&self.0, 65 as Uint);
        let c_leq_90 = k.k.scalar_le_parallelized(&self.0, 90 as Uint);
        binary_and(k, &c_geq_65, &c_leq_90)
    }

    /// Returns whether `self` is lowercase.
    pub fn is_lowercase(&self, k: &ServerKey) -> RadixCiphertext {
        // (97 <= c <= 122)
        let c_geq_97 = k.k.scalar_ge_parallelized(&self.0, 97 as Uint);
        let c_leq_122 = k.k.scalar_le_parallelized(&self.0, 122 as Uint);
        binary_and(k, &c_geq_97, &c_leq_122)
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

impl FheString {
    /// Returns a copy of `self` where uppercase characters have been replaced
    /// by their lowercase counterparts.
    pub fn to_lowercase(&self, k: &ServerKey) -> FheString {
        let v = self.0.par_iter().map(|c| c.to_lowercase(k)).collect();
        FheString(v)
    }

    /// Returns a copy of `self` where lowercase characters have been replaced
    /// by their uppercase counterparts.
    pub fn to_uppercase(&self, k: &ServerKey) -> FheString {
        let v = self.0.par_iter().map(|c| c.to_uppercase(k)).collect();
        FheString(v)
    }
}
