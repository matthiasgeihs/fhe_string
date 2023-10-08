use tfhe::integer::RadixClientKey;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey(pub(crate) RadixClientKey);

pub trait Key {
    /// Returns the maximum value that can be stored in a ciphertext.
    fn max_int(&self) -> usize;
}

impl Key for ClientKey {
    fn max_int(&self) -> usize {
        let msg_mod = self.0.parameters().message_modulus().0;
        let blocks = self.0.num_blocks();
        msg_mod.pow(blocks as u32) - 1
    }
}
