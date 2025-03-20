/*!
Core traits for cryptographic operations.

This module defines the interfaces for the various cryptographic
operations supported by the system.
*/

pub mod cipher;
pub mod kex;
pub mod signature;

// Re-export core traits for easier access
pub use cipher::SymmetricCipher;
pub use kex::KeyExchange;
pub use signature::Signature;