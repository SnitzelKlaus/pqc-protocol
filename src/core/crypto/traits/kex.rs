/*!
Traits for key exchange operations.

This module defines the interfaces for key exchange operations.
*/

use crate::core::crypto::types::errors::Result;
use crate::core::crypto::types::algorithms::KeyExchangeAlgorithm;

/// Trait for key exchange operations
pub trait KeyExchange: Send + Sync {
    /// Generate a key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Encapsulate a shared secret using the receiver's public key (sender side)
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Decapsulate a shared secret from a ciphertext (receiver side)
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>;
    
    /// Derive a symmetric encryption key from the shared secret
    fn derive_encryption_key(&self, shared_secret: &[u8]) -> Result<[u8; 32]>;
    
    /// Get the current algorithm
    fn algorithm(&self) -> KeyExchangeAlgorithm;
    
    /// Get the public key size for this algorithm
    fn public_key_size(&self) -> usize;
    
    /// Get the ciphertext size for this algorithm
    fn ciphertext_size(&self) -> usize;
}