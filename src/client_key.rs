use tfhe::integer::RadixClientKey;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClientKey(pub(crate) RadixClientKey);

impl ClientKey {
    pub fn max_int(&self) -> usize {
        let msg_mod = self.0.parameters().message_modulus().0;
        let blocks = self.0.num_blocks();
        msg_mod.pow(blocks as u32) - 1
    }
}
