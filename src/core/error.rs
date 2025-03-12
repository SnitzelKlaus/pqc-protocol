/*!
Improved error handling for the PQC protocol.

This module extends the current error handling with more context,
better debugging, and more security-conscious errors.
*/

use std::io;
use std::fmt;
use thiserror::Error;

/// Result type for the PQC protocol
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the PQC protocol
#[derive(Error, Debug)]
pub enum Error {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Cryptographic error (limited details for security)
    #[error("Cryptographic operation failed")]
    Crypto(#[source] CryptoError),
    
    /// Invalid sequence number
    #[error("Message sequence error")]
    InvalidSequence(u32, u32),
    
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    
    /// Authentication error (limited details for security)
    #[error("Authentication failed")]
    Authentication(#[source] AuthError),
    
    /// Session not initialized
    #[error("Session not in correct state: expected {expected}, but was {actual}")]
    InvalidState {
        expected: String,
        actual: String,
    },
    
    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    
    /// Key exchange error (limited details for security)
    #[error("Key exchange failed")]
    KeyExchange(#[source] KeyExchangeError),
    
    /// Memory error
    #[error("Memory operation failed: {0}")]
    Memory(String),
    
    /// Rate limit error
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    /// Timeout error
    #[error("Operation timed out after {0} ms")]
    Timeout(u64),
}

/// Cryptographic errors with limited details to prevent leaking information
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Generic encryption error
    #[error("Encryption failed")]
    EncryptionFailed,
    
    /// Generic decryption error
    #[error("Decryption failed")]
    DecryptionFailed,
    
    /// Key derivation error
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    
    /// Generic cryptographic operation error
    #[error("Cryptographic operation failed")]
    OperationFailed,
    
    /// Invalid key format
    #[error("Invalid key format")]
    InvalidKeyFormat,
}

/// Authentication errors with limited details to prevent leaking information
#[derive(Error, Debug)]
pub enum AuthError {
    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    /// Missing verification key
    #[error("Verification key not available")]
    MissingVerificationKey,
    
    /// Invalid key format
    #[error("Invalid key format")]
    InvalidKeyFormat,
    
    /// Authentication timeout
    #[error("Authentication timed out")]
    Timeout,
}

/// Key exchange errors with limited details to prevent leaking information
#[derive(Error, Debug)]
pub enum KeyExchangeError {
    /// Key generation failed
    #[error("Key generation failed")]
    KeyGenerationFailed,
    
    /// Key encapsulation failed
    #[error("Key encapsulation failed")]
    EncapsulationFailed,
    
    /// Key decapsulation failed
    #[error("Key decapsulation failed")]
    DecapsulationFailed,
    
    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    /// Invalid ciphertext
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// Error context for adding more information to errors
#[derive(Debug)]
pub struct ErrorContext {
    /// The error that occurred
    pub error: Error,
    /// Additional context about the error
    pub context: String,
    /// File where the error occurred
    pub file: &'static str,
    /// Line where the error occurred
    pub line: u32,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (at {}:{}) - {}",
            self.error, self.file, self.line, self.context
        )
    }
}

impl std::error::Error for ErrorContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Add context to an error
#[macro_export]
macro_rules! with_context {
    ($error:expr, $context:expr) => {
        $crate::error::ErrorContext {
            error: $error,
            context: $context.to_string(),
            file: file!(),
            line: line!(),
        }
    };
}

/// Create a protocol error with context
#[macro_export]
macro_rules! protocol_err {
    ($msg:expr) => {
        Err($crate::error::Error::Protocol($msg.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        Err($crate::error::Error::Protocol(format!($fmt, $($arg)*)))
    };
}

/// Create a crypto error with context
#[macro_export]
macro_rules! crypto_err {
    ($err:expr) => {
        Err($crate::error::Error::Crypto($err))
    };
}

/// Create an authentication error with context
#[macro_export]
macro_rules! auth_err {
    ($err:expr) => {
        Err($crate::error::Error::Authentication($err))
    };
}

/// Create a key exchange error with context
#[macro_export]
macro_rules! key_exchange_err {
    ($err:expr) => {
        Err($crate::error::Error::KeyExchange($err))
    };
}

/// Create an invalid state error with context
#[macro_export]
macro_rules! invalid_state_err {
    ($expected:expr, $actual:expr) => {
        Err($crate::error::Error::InvalidState {
            expected: $expected.to_string(),
            actual: $actual.to_string(),
        })
    };
}

/// Convert from Error to io::Error (for compatibility)
impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(io_error) => io_error,
            Error::Protocol(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::Crypto(_) => io::Error::new(io::ErrorKind::InvalidData, "Cryptographic error"),
            Error::InvalidSequence(_, _) => {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid sequence number")
            }
            Error::InvalidFormat(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::Authentication(_) => {
                io::Error::new(io::ErrorKind::PermissionDenied, "Authentication error")
            }
            Error::InvalidState { expected, actual } => io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Invalid state: expected {}, but was {}", expected, actual),
            ),
            Error::UnsupportedVersion(ver) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported protocol version: {}", ver),
            ),
            Error::Internal(msg) => io::Error::new(io::ErrorKind::Other, msg),
            Error::KeyExchange(_) => {
                io::Error::new(io::ErrorKind::ConnectionRefused, "Key exchange error")
            }
            Error::Memory(msg) => io::Error::new(io::ErrorKind::Other, msg),
            Error::RateLimit(msg) => io::Error::new(io::ErrorKind::ConnectionRefused, msg),
            Error::Timeout(ms) => io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Operation timed out after {} ms", ms),
            ),
        }
    }
}

/// Convert from ErrorContext to io::Error (for compatibility)
impl From<ErrorContext> for io::Error {
    fn from(ctx: ErrorContext) -> Self {
        // Borrow the error for its string representation.
        let error_str = format!("{}", &ctx.error);
        // Now move the error into io::Error to extract its kind.
        let kind = io::Error::from(ctx.error).kind();
        io::Error::new(kind, format!("{} - {}", error_str, ctx.context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = Error::Protocol("Test error".to_string());
        assert_eq!(format!("{}", err), "Protocol error: Test error");
        
        let err = Error::InvalidSequence(1, 2);
        assert_eq!(format!("{}", err), "Message sequence error");
        
        let err = Error::UnsupportedVersion(42);
        assert_eq!(format!("{}", err), "Unsupported protocol version: 42");
    }
    
    #[test]
    fn test_error_context() {
        let err = Error::Protocol("Test error".to_string());
        let ctx = with_context!(err, "Additional context");
        
        assert!(format!("{}", ctx).contains("Protocol error: Test error"));
        assert!(format!("{}", ctx).contains("Additional context"));
        assert!(format!("{}", ctx).contains(file!()));
    }
    
    #[test]
    fn test_io_error_conversion() {
        let err = Error::Protocol("Test error".to_string());
        let io_err = io::Error::from(err);
        
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{}", io_err).contains("Test error"));
    }
}