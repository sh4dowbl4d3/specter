use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    #[error("Decode error: {0}")]
    Decode(String),

    #[error("Encode error: {0}")]
    Encode(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
