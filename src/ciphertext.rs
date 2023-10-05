use crate::{client_key::ClientKey, error::Error, server_key::ServerKey};
use tfhe::integer::RadixCiphertext;

/// FheAsciiChar is a wrapper type for RadixCiphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheAsciiChar(pub(crate) RadixCiphertext);

/// FheString is a wrapper type for Vec<FheAsciiChar>. It is assumed to be
/// 0-terminated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FheString(pub(crate) Vec<FheAsciiChar>);

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
        } else if s.len() > k.max_int() - 1 {
            return Err("string length exceeds maximum length".into());
        } else if l > k.max_int() - 1 {
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

    /// Returns the length of the encrypted string.
    pub fn len(&self, k: &ServerKey) -> RadixCiphertext {
        let zero = k.create_zero();
        let one = k.create_one();

        let mut l = zero.clone(); // Length.
        let mut b = zero.clone(); // String terminated.

        // l = b * l + (1 - b) * (e == 0) * i
        // b = b || e == 0

        self.0.iter().enumerate().for_each(|(i, e)| {
            println!("len: at index {i}");
            let b_mul_l = k.k.mul_parallelized(&b, &l);

            let e_eq_0 = k.k.scalar_eq_parallelized(&e.0, 0);
            let e_eq_0_mul_i = k.k.scalar_mul_parallelized(&e_eq_0, i as u64);

            let not_b = k.k.sub_parallelized(&one, &b);
            let not_b_mul_e_eq_0_mul_i = k.k.mul_parallelized(&not_b, &e_eq_0_mul_i);

            l = k.k.add_parallelized(&b_mul_l, &not_b_mul_e_eq_0_mul_i);
            b = binary_or(&k, &b, &e_eq_0);
        });

        l
    }

    /// Returns whether `self` contains the string `s`. The result is an
    /// encryption of 1 if this is the case and an encryption of 0 otherwise.
    pub fn contains(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
        let zero = k.create_zero();
        let mut b = zero.clone(); // Pattern contained.

        (0..self.0.len() - s.0.len() + 1).for_each(|i| {
            println!("contains: at index {i}");
            let eq = self.substr(k, i, s.0.len() - 1).equals(k, s);

            // b = b || eq
            b = binary_or(&k, &b, &eq);
        });

        b
    }

    /// Returns the substring of the encrypted string starting at index i and
    /// having length l.
    ///
    /// # Panics
    /// Panics on index out of bound.
    fn substr(&self, k: &ServerKey, i: usize, l: usize) -> Self {
        let mut v = self.0[i..i + l].to_vec();

        // Append zero if not end of string.
        if i + l < self.0.len() {
            let zero = FheAsciiChar(k.create_zero());
            v.push(zero);
        }
        FheString(v)
    }

    /// Returns whether `self` and `s` are equal. The result is an encryption of
    /// 1 if this is the case and an encryption of 0 otherwise.
    pub fn equals(&self, k: &ServerKey, s: &FheString) -> RadixCiphertext {
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

        // is_equal = is_equal && ai == bi
        a.0.iter().zip(b.0).for_each(|(ai, bi)| {
            let ai_eq_bi = k.k.eq_parallelized(&ai.0, &bi.0);
            is_equal = k.k.mul_parallelized(&is_equal, &ai_eq_bi);
        });
        is_equal
    }

    /// Returns a copy of `self` padded to the given length.
    ///
    /// # Panics
    /// Panics if l exceeds the maximum length.
    fn pad(&self, k: &ServerKey, l: usize) -> Self {
        if l > k.max_int() - 1 {
            panic!("pad length exceeds maximum length")
        }

        let mut v = self.0.to_vec();
        let zero = FheAsciiChar(k.create_zero());
        (0..l - self.0.len()).for_each(|_| v.push(zero.clone()));
        FheString(v)
    }
}

// Returns `a or b`, assuming `a` and `b` are encryptions of binary values.
pub fn binary_or(k: &ServerKey, a: &RadixCiphertext, b: &RadixCiphertext) -> RadixCiphertext {
    // a + b - a * b
    let a_add_b = k.k.add_parallelized(a, b);
    let a_mul_b = k.k.mul_parallelized(a, b);
    k.k.sub_parallelized(&a_add_b, &a_mul_b)
}
