/*!
Message handling for the PQC protocol.

This module provides types and utilities for working with protocol messages,
including message types, headers, and formatting.
*/

pub mod types;
pub mod format;

// Re-export commonly used items
pub use types::{MessageType, ErrorCode};
pub use format::{MessageHeader, MessageBuilder, MessageParser};