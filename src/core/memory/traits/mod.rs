/*!
Core traits for memory security.

This module provides the core traits that define memory security capabilities.
*/

pub mod protection;
pub mod security;
pub mod zeroize;

// Re-export core traits
pub use zeroize::Zeroize;
pub use protection::MemoryProtection;
pub use security::{MemorySecurity, SecureSession, SecureMemoryFactory};