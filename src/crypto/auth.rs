/*!
Authentication functionality for the PQC protocol.

This module provides functions for digital signatures and verification
using Dilithium.
*/

use crate::error::{Result, Error};
use crate::error::AuthError;

use pqcrypto_dilithium::{
    dilithium3,
    dilithium3::{
        PublicKey as DilithiumPublicKey,
        SecretKey as DilithiumSecretKey,
        DetachedSignature as DilithiumSignature,
    },
};

use pqcrypto_traits::sign::DetachedSignature;

/// Authentication handler for digital signatures
pub struct Authentication;

impl Authentication {
    /// Generate a new Dilithium key pair
    pub fn generate_keypair() -> (DilithiumPublicKey, DilithiumSecretKey) {
        dilithium3::keypair()
    }
    
    /// Sign data using a Dilithium signing key
    pub fn sign(data: &[u8], secret_key: &DilithiumSecretKey) -> DilithiumSignature {
        dilithium3::detached_sign(data, secret_key)
    }
    
    /// Verify a signature using a Dilithium verification key
    pub fn verify(
        data: &[u8],
        signature: &DilithiumSignature,
        public_key: &DilithiumPublicKey,
    ) -> Result<()> {
        match dilithium3::verify_detached_signature(signature, data, public_key) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::Authentication(AuthError::SignatureVerificationFailed)),
        }
    }
    
    /// Get the size of a Dilithium signature in bytes
    pub fn signature_size() -> usize {
        dilithium3::signature_bytes()
    }
    
    /// Create a signature from bytes
    pub fn signature_from_bytes(bytes: &[u8]) -> Result<DilithiumSignature> {
        match DilithiumSignature::from_bytes(bytes) {
            Ok(sig) => Ok(sig),
            Err(_) => Err(Error::Authentication(AuthError::InvalidKeyFormat)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_verification() {
        let (public_key, secret_key) = Authentication::generate_keypair();
        let data = b"This is a test message to sign";
        
        let signature = Authentication::sign(data, &secret_key);
        let result = Authentication::verify(data, &signature, &public_key);
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_signature() {
        let (public_key, secret_key) = Authentication::generate_keypair();
        let data = b"This is a test message to sign";
        let different_data = b"This is a different message";
        
        let signature = Authentication::sign(data, &secret_key);
        
        // Signature should not verify for different data
        let result = Authentication::verify(different_data, &signature, &public_key);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_signature_from_bytes() {
        let (public_key, secret_key) = Authentication::generate_keypair();
        let data = b"This is a test message to sign";
        
        let signature = Authentication::sign(data, &secret_key);
        let signature_bytes = signature.as_bytes();
        
        let reconstructed = Authentication::signature_from_bytes(signature_bytes).unwrap();
        let result = Authentication::verify(data, &reconstructed, &public_key);
        
        assert!(result.is_ok());
    }
}
