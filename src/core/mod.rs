//! Core components for the PQC protocol.
//!
//! This module contains the fundamental building blocks of the protocol,
//! including cryptographic primitives, message formats, session management,
//! and error handling.

// Export cryptographic functionality
pub mod crypto;

// Export message handling
pub mod message;

// Export session management
pub mod session;

// Export memory handling for sensitive data
pub mod memory;

// Export security utilities
pub mod security;

// Protocol constants
pub mod constants;

// Error handling
pub mod error;

// Re-exports for convenience
pub use self::error::{Error, Result, AuthError, CryptoError, KeyExchangeError};
pub use self::message::{types::MessageType, format::MessageHeader};
pub use self::session::{state::SessionState, state::Role};
pub use self::constants::VERSION;