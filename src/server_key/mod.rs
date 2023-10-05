use tfhe::integer::ServerKey as IntegerServerKey;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerKey(pub(crate) IntegerServerKey);
