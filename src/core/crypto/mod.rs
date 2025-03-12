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

// Kyber types
pub use pqcrypto_kyber::kyber768::{
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    Ciphertext as KyberCiphertext
};

// Dilithium types
pub use pqcrypto_dilithium::dilithium3::{
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    DetachedSignature as DilithiumSignature
};

pub use cipher::Cipher;