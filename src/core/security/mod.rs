/*!
Security utilities for the PQC protocol.

This module provides various security-related utilities like
constant-time operations and key rotation mechanisms.
*/

// Constant-time operations to prevent timing attacks
pub mod constant_time;

// Hardware security module integration
pub mod hardware_security;

// Key rotation for forward secrecy
pub mod rotation;

// Re-export main components
pub use constant_time::{constant_time_eq, constant_time_select, constant_time_increment};
pub use rotation::{KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation};
pub use hardware_security::{HardwareSecurityManager, HardwareSecurityCapability};