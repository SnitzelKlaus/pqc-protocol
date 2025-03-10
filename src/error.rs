/*!
Error handling for the PQC protocol.
*/

use std::io;
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
    
    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Invalid sequence number
    #[error("Invalid sequence number")]
    InvalidSequence,
    
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    
    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    /// Session not initialized
    #[error("Session not initialized")]
    SessionNotInitialized,
    
    /// Unsupported protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    
    /// Key exchange error
    #[error("Key exchange error: {0}")]
    KeyExchange(String),
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(io_error) => io_error,
            Error::Protocol(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::Crypto(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::InvalidSequence => io::Error::new(io::ErrorKind::InvalidData, "Invalid sequence number"),
            Error::InvalidFormat(msg) => io::Error::new(io::ErrorKind::InvalidData, msg),
            Error::Authentication(msg) => io::Error::new(io::ErrorKind::PermissionDenied, msg),
            Error::SessionNotInitialized => io::Error::new(io::ErrorKind::NotConnected, "Session not initialized"),
            Error::UnsupportedVersion(ver) => io::Error::new(
                io::ErrorKind::InvalidData, 
                format!("Unsupported protocol version: {}", ver)
            ),
            Error::Internal(msg) => io::Error::new(io::ErrorKind::Other, msg),
            Error::KeyExchange(msg) => io::Error::new(io::ErrorKind::ConnectionRefused, msg),
        }
    }
}

/// Convert a string to an Error::Protocol
pub fn protocol_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::Protocol(msg.into()))
}

/// Convert a string to an Error::Crypto
pub fn crypto_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::Crypto(msg.into()))
}

/// Convert a string to an Error::Internal
pub fn internal_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::Internal(msg.into()))
}

/// Convert a string to an Error::InvalidFormat
pub fn format_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::InvalidFormat(msg.into()))
}

/// Convert a string to an Error::Authentication
pub fn auth_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::Authentication(msg.into()))
}

/// Convert a string to an Error::KeyExchange
pub fn key_exchange_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::KeyExchange(msg.into()))
}