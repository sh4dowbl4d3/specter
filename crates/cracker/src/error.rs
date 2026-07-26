use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrackerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("No wordlist loaded")]
    NoWordlist,
}
