/*!
Core types for cryptographic operations.

This module provides the type definitions, enums, and constants
used throughout the cryptographic subsystem.
*/

pub mod algorithms;
pub mod errors;
pub mod constants;
pub mod config;

// Re-export core types for easier access
pub use algorithms::{KeyExchangeAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
pub use errors::{Error, Result};
pub use config::CryptoConfig;