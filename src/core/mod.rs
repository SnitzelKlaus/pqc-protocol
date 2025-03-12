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

// Re-export commonly used types for convenience
pub use error::{Error, Result};
pub use message::{MessageType, MessageHeader};
pub use session::{PqcSession, SessionState, Role};
pub use constants::VERSION;