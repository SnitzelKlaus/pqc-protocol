/*!
Core traits for memory security.

This module provides the core traits that define memory security capabilities.
*/

pub mod protection;
pub mod security;

// Re-export core traits
pub use protection::MemoryProtection;
pub use security::{MemorySecurity, SecureSession, SecureMemoryFactory};

// Re-export the Zeroize trait from the external crate
pub use zeroize::Zeroize;