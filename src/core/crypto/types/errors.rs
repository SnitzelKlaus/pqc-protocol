/*!
Error types for cryptographic operations.

This module defines the various error types that can occur during
cryptographic operations.
*/

use std::fmt;
use std::error::Error as StdError;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for cryptographic operations
#[derive(Debug)]
pub enum Error {
    /// Encryption failed
    EncryptionFailed,
    
    /// Decryption failed
    DecryptionFailed,
    
    /// Key derivation failed
    KeyDerivationFailed,
    
    /// Invalid key format
    InvalidKeyFormat,
    
    /// Invalid signature format
    InvalidSignatureFormat,
    
    /// Signature verification failed
    SignatureVerificationFailed,
    
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
    
    /// Authentication error
    Authentication(AuthError),
    
    /// Generic error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Error::InvalidKeyFormat => write!(f, "Invalid key format"),
            Error::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            Error::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Error::UnsupportedAlgorithm(msg) => write!(f, "Unsupported algorithm: {}", msg),
            Error::Authentication(e) => write!(f, "Authentication error: {}", e),
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl StdError for Error {}

/// Authentication-specific error type
#[derive(Debug)]
pub enum AuthError {
    /// Signature verification failed
    SignatureVerificationFailed,
    
    /// Missing verification key
    MissingVerificationKey,
    
    /// Invalid key format
    InvalidKeyFormat,
    
    /// Invalid signature format
    InvalidSignatureFormat,
    
    /// Authentication timeout
    Timeout,
    
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
}

impl AuthError {
    /// Create an UnsupportedAlgorithm error
    pub fn unsupported_algorithm(msg: &str) -> Self {
        AuthError::UnsupportedAlgorithm(msg.to_string())
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            AuthError::MissingVerificationKey => write!(f, "Verification key not available"),
            AuthError::InvalidKeyFormat => write!(f, "Invalid key format"),
            AuthError::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            AuthError::Timeout => write!(f, "Authentication timed out"),
            AuthError::UnsupportedAlgorithm(msg) => write!(f, "Unsupported algorithm: {}", msg),
        }
    }
}

impl StdError for AuthError {}

/// Macro for creating authentication errors
#[macro_export]
macro_rules! auth_err {
    ($err:expr) => {
        crate::core::crypto::types::errors::Error::Authentication($err)
    };
}