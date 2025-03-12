/*!
Session management for the PQC protocol.

This module provides session state management and handles the lifecycle
of a protocol session, including key exchange, authentication, and data transfer.
*/

pub mod state;
pub mod manager;

// Re-export commonly used items
pub use state::{SessionState, Role, StateManager};
pub use manager::SessionManager;

// Define a type alias for backward compatibility
/// PqcSession is the main session type for the protocol
pub type PqcSession = SessionManager;