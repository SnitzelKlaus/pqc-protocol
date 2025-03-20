/*!
Cryptographic components for the PQC protocol.

This module provides the cryptographic primitives used in the protocol,
including key exchange, digital signatures, and symmetric encryption.
*/

// Public API
pub mod api;

// Core types
pub mod types;

// Traits
pub mod traits;

// Algorithm implementations
pub mod algorithms;

// Registry for algorithm management
pub mod registry;

// Re-export frequently used types
pub use types::algorithms::{
    KeyExchangeAlgorithm,
    SignatureAlgorithm,
    SymmetricAlgorithm,
};

pub use types::errors::{Error, Result};

// Re-export high-level API
pub use api::{
    create_crypto_config,
    generate_keypair,
    encrypt_data,
    decrypt_data,
    sign_data,
    verify_signature,
    derive_encryption_key,
};

// Re-export configuration types
pub use types::config::CryptoConfig;