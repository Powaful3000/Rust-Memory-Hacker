use thiserror::Error;
use tokio::task::JoinError;

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("Failed to access process: {0}")]
    ProcessAccess(String),
    
    #[error("Memory operation failed: {0}")]
    MemoryOperation(String),
    
    #[error("Invalid address: {0:x}")]
    InvalidAddress(usize),
    
    #[error("Memory alignment error at address {0:x}: required alignment {1}")]
    AlignmentError(usize, usize),
    
    #[error("Invalid memory protection at address {0:x}")]
    InvalidProtection(usize),
    
    #[error("System error: {0}")]
    System(#[from] std::io::Error),
    
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
}

pub type Result<T> = std::result::Result<T, MemoryError>; 