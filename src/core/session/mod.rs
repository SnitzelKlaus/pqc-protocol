/*!
Session management for the PQC protocol.

This module provides the session management functionality, including
state machine, key management, and protocol operations.
*/

// State management
pub mod state;

// Key management
pub mod key_manager;

// Authentication
pub mod auth_manager;

// Data management
pub mod data_manager;

// Main session implementation
pub mod session;

// Re-export main session types
pub use self::state::{SessionState, Role};
pub use self::session::Session;

// Define the public PqcSession type (main API)
pub type PqcSession = Session;