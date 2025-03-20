/*!
Traits for signature operations.

This module defines the interfaces for signature operations.
*/

use crate::core::crypto::types::errors::Result;
use crate::core::crypto::types::algorithms::SignatureAlgorithm;

/// Trait for signature operations
pub trait Signature: Send + Sync {
    /// Generate a key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Sign data
    fn sign(&self, data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>;
    
    /// Verify a signature
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()>;
    
    /// Get the current algorithm
    fn algorithm(&self) -> SignatureAlgorithm;
    
    /// Get the signature size for this algorithm
    fn signature_size(&self) -> usize;
    
    /// Get the public key size for this algorithm
    fn public_key_size(&self) -> usize;
}