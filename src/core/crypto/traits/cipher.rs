/*!
Traits for symmetric encryption and decryption.

This module defines the interfaces for symmetric ciphers.
*/

use crate::core::crypto::types::errors::Result;
use crate::core::crypto::types::algorithms::SymmetricAlgorithm;

/// Trait for symmetric cipher operations
pub trait SymmetricCipher: Send + Sync {
    /// Encrypt data with the cipher
    fn encrypt(&self, nonce: &chacha20poly1305::Nonce, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data with the cipher
    fn decrypt(&self, nonce: &chacha20poly1305::Nonce, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Get the algorithm being used
    fn algorithm(&self) -> SymmetricAlgorithm;
    
    /// Check if the cipher is initialized
    fn is_initialized(&self) -> bool;
}