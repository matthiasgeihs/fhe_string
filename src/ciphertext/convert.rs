//! Functionality for string conversion.

use rayon::prelude::*;
use tfhe::integer::BooleanBlock;

use crate::server_key::ServerKey;

use super::{FheAsciiChar, FheString, Uint};

impl FheAsciiChar {
    const CASE_DIFF: u8 = 32;

    /// Returns whether `self` is uppercase.
    pub fn is_uppercase(&self, k: &ServerKey) -> BooleanBlock {
        // (65 <= c <= 90)
        let c_geq_65 = k.k.scalar_ge_parallelized(&self.0, 65 as Uint);
        let c_leq_90 = k.k.scalar_le_parallelized(&self.0, 90 as Uint);
        k.k.boolean_bitand(&c_geq_65, &c_leq_90)
    }

    /// Returns whether `self` is lowercase.
    pub fn is_lowercase(&self, k: &ServerKey) -> BooleanBlock {
        // (97 <= c <= 122)
        let c_geq_97 = k.k.scalar_ge_parallelized(&self.0, 97 as u8);
        let c_leq_122 = k.k.scalar_le_parallelized(&self.0, 122 as u8);
        k.k.boolean_bitand(&c_geq_97, &c_leq_122)
    }

    /// Returns the lowercase representation of `self`.
    pub fn to_lowercase(&self, k: &ServerKey) -> FheAsciiChar {
        // c + (c.uppercase ? 32 : 0)
        let ucase = self.is_uppercase(k);
        let self_add_32 = k.k.scalar_add_parallelized(&self.0, Self::CASE_DIFF as u8);
        let lcase = k.k.if_then_else_parallelized(&ucase, &self_add_32, &self.0);
        FheAsciiChar(lcase)
    }

    /// Returns the uppercase representation of `self`.
    pub fn to_uppercase(&self, k: &ServerKey) -> FheAsciiChar {
        // c - (c.lowercase ? 32 : 0)
        let lcase = self.is_lowercase(k);
        let self_sub_32 = k.k.scalar_sub_parallelized(&self.0, Self::CASE_DIFF);
        let ucase = k.k.if_then_else_parallelized(&lcase, &self_sub_32, &self.0);
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
