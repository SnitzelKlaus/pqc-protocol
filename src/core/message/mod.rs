/*!
Message handling for the PQC protocol.

This module contains types and functions for creating, parsing, and
manipulating protocol messages.
*/

// Message types
pub mod types;

// Message format
pub mod format;

// Re-export main types for convenience
pub use self::types::MessageType;
pub use self::format::{MessageHeader, MessageBuilder, MessageParser};