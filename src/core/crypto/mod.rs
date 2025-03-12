/*!
Cryptographic components for the PQC protocol.

This module provides the cryptographic primitives used in the protocol,
including key exchange, digital signatures, and symmetric encryption.
*/

// Key exchange functionality
pub mod key_exchange;

// Authentication and signatures
pub mod auth;

// Symmetric encryption
pub mod cipher;

// Re-export frequently used types
pub use key_exchange::{KyberPublicKey, KyberSecretKey, KyberCiphertext};
pub use auth::{DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
pub use cipher::Cipher;