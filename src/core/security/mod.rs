/*!
Security utilities for the PQC protocol.

This module provides various security-related utilities like
constant-time operations and key rotation mechanisms.
*/

// Key rotation for forward secrecy
pub mod rotation;

// Re-export main components
pub use rotation::{KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation};