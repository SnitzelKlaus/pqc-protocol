/*!
Hardware security module interfaces for the PQC protocol.

This module provides interfaces to hardware security modules (HSMs)
for secure key storage, signing, and random number generation.
*/

pub mod hsm;

// Re-export the main components
pub use hsm::{HardwareSecurityManager, HardwareSecurityCapability, HsmType};