/*!
Cryptographic functionality for the PQC protocol.

This module provides cryptographic operations for the protocol,
including key exchange, encryption, and digital signatures.
*/

pub mod key_exchange;
pub mod cipher;
pub mod auth;

// Re-export commonly used items
pub use key_exchange::KeyExchange;
pub use cipher::Cipher;
pub use auth::Authentication;

// Re-export common cryptographic types
pub use pqcrypto_kyber::kyber768::{
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    Ciphertext as KyberCiphertext,
};

pub use pqcrypto_dilithium::dilithium3::{
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    DetachedSignature as DilithiumSignature,
};

pub use chacha20poly1305::Nonce;