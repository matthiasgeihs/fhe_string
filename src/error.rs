use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct Error {
    pub desc: String,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.desc)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self { desc: value }
    }
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self {
            desc: value.to_string(),
        }
    }
}
