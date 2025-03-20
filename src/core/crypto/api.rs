/*!
Public API for cryptographic operations.

This module provides a simple and consistent API for cryptographic operations,
hiding the complexity of the underlying implementations.
*/

use crate::core::crypto::types::algorithms::{
    KeyExchangeAlgorithm,
    SignatureAlgorithm,
    SymmetricAlgorithm,
};
use crate::core::crypto::types::config::CryptoConfig;
use crate::core::crypto::types::errors::Result;
use crate::core::crypto::algorithms::kex::create_key_exchange;
use crate::core::crypto::algorithms::signatures::create_authenticator;
use crate::core::crypto::algorithms::symmetric::create_cipher;
use crate::core::message::types::MessageType;

/// Create a default crypto configuration
pub fn create_crypto_config() -> CryptoConfig {
    CryptoConfig::default()
}

/// Create a crypto configuration with specific settings
pub fn create_custom_config(
    key_exchange: KeyExchangeAlgorithm,
    signature: SignatureAlgorithm,
    symmetric: SymmetricAlgorithm,
) -> CryptoConfig {
    CryptoConfig::with_algorithms(key_exchange, signature, symmetric)
}

/// Generate a key pair for the specified key exchange algorithm
pub fn generate_kex_keypair(algorithm: KeyExchangeAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
    let kex = create_key_exchange(algorithm)?;
    kex.generate_keypair()
}

/// Generate a key pair for the specified signature algorithm
pub fn generate_signature_keypair(algorithm: SignatureAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {
    let auth = create_authenticator(algorithm)?;
    auth.generate_keypair()
}

/// Generate a key pair based on the crypto configuration
pub fn generate_keypair(config: &CryptoConfig) -> Result<(Vec<u8>, Vec<u8>)> {
    let kex = create_key_exchange(config.key_exchange)?;
    kex.generate_keypair()
}

/// Encapsulate a shared secret (sender side)
pub fn encapsulate(algorithm: KeyExchangeAlgorithm, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kex = create_key_exchange(algorithm)?;
    kex.encapsulate(public_key)
}

/// Decapsulate a shared secret (receiver side)
pub fn decapsulate(
    algorithm: KeyExchangeAlgorithm,
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let kex = create_key_exchange(algorithm)?;
    kex.decapsulate(ciphertext, secret_key)
}

/// Derive an encryption key from a shared secret
pub fn derive_encryption_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let kex = create_key_exchange(KeyExchangeAlgorithm::Kyber768)?;
    kex.derive_encryption_key(shared_secret)
}

/// Encrypt data using the specified algorithm
pub fn encrypt_data(
    algorithm: SymmetricAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = create_cipher(key, algorithm)?;
    let nonce_array = chacha20poly1305::Nonce::from_slice(nonce);
    cipher.encrypt(nonce_array, data)
}

/// Decrypt data using the specified algorithm
pub fn decrypt_data(
    algorithm: SymmetricAlgorithm,
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = create_cipher(key, algorithm)?;
    let nonce_array = chacha20poly1305::Nonce::from_slice(nonce);
    cipher.decrypt(nonce_array, data)
}

/// Create a nonce from sequence number and message type
pub fn create_nonce(seq_num: u32, msg_type: MessageType) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    
    // First 4 bytes: sequence number
    nonce[0..4].copy_from_slice(&seq_num.to_be_bytes());
    
    // 5th byte: message type
    nonce[4] = msg_type.as_u8();
    
    // Last 7 bytes: fixed data (all zeros)
    // Already initialized to zero
    
    nonce
}

/// Sign data using the specified algorithm
pub fn sign_data(
    algorithm: SignatureAlgorithm,
    secret_key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let auth = create_authenticator(algorithm)?;
    auth.sign(data, secret_key)
}

/// Verify a signature using the specified algorithm
pub fn verify_signature(
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    let auth = create_authenticator(algorithm)?;
    auth.verify(data, signature, public_key)
}

/// Get the signature size for the specified algorithm
pub fn signature_size(algorithm: SignatureAlgorithm) -> Result<usize> {
    let auth = create_authenticator(algorithm)?;
    Ok(auth.signature_size())
}

/// Get the public key size for the specified algorithm
pub fn public_key_size(algorithm: SignatureAlgorithm) -> Result<usize> {
    let auth = create_authenticator(algorithm)?;
    Ok(auth.public_key_size())
}