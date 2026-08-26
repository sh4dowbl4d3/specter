use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Decode error: {0}")]
    Decode(String),

    #[error("Encode error: {0}")]
    Encode(String),
}
