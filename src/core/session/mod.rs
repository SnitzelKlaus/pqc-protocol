/*!
Session management for the PQC protocol.

This module provides the session management functionality, including
state machine, key management, and protocol operations.
*/

// State management
pub mod state;

// Session manager
pub mod manager;

// Re-export main session types
pub use self::state::{SessionState, Role};
pub use self::manager::SessionManager;

// Define the public PqcSession type (main API)
pub type PqcSession = SessionManager;