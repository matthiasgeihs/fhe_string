use tfhe::integer::RadixClientKey;

use crate::{
    ciphertext::{FheAsciiChar, FheString},
    error::Error,
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey(pub(crate) RadixClientKey);

impl ClientKey {
    /// Encrypts an ascii string into an FheString. The input string must only
    /// contain ascii characters and must not contain any zero values. The
    /// result is padded to the given length.
    ///
    /// # Arguments
    ///
    /// * `s` - The string to be encrypted.
    /// * `k` - The client key.
    /// * `l` - The length to pad to.
    pub fn encrypt(&self, s: &str, l: usize) -> Result<FheString, Error> {
        if !s.is_ascii() {
            return Err("string is not ascii".into());
        } else if s.chars().find(|&x| x as u8 == 0).is_some() {
            return Err("string contains 0 char".into());
        } else if s.len() > self.max_int() - 1 {
            return Err("string length exceeds maximum length".into());
        } else if l > self.max_int() - 1 {
            return Err("pad length exceeds maximum length".into());
        } else if l < s.len() {
            return Err("string length exceeds pad length".into());
        }

        // Encrypt characters.
        let mut fhe_chars = s
            .chars()
            .map(|c| {
                let ct = self.0.encrypt(c as u8);
                FheAsciiChar(ct)
            })
            .collect::<Vec<_>>();

        // Append zero char.
        let zero = self.0.encrypt(0u8);
        let zero = FheAsciiChar(zero);
        fhe_chars.push(zero.clone());

        // Pad to length.
        (0..l + 1 - fhe_chars.len()).for_each(|_| fhe_chars.push(zero.clone()));

        Ok(FheString(fhe_chars))
    }

    pub fn max_int(&self) -> usize {
        let msg_mod = self.0.parameters().message_modulus().0;
        let blocks = self.0.num_blocks();
        msg_mod.pow(blocks as u32) - 1
    }
}
