use thiserror::Error;
use tokio::task::JoinError;
use std::num::{ParseIntError, ParseFloatError};
use dialoguer;

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

    #[error("Dialog error: {0}")]
    DialogError(#[from] dialoguer::Error),

    #[error("Integer parse error: {0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("Float parse error: {0}")]
    ParseFloatError(#[from] ParseFloatError),
}

pub type Result<T> = std::result::Result<T, MemoryError>; 