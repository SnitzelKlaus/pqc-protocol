/*!
Authentication management for the PQC protocol.

This module provides functionality for handling the authentication phase
of the protocol, including signature generation and verification.
*/

use crate::core::{
    error::{Result, Error, AuthError},
    crypto::{
        auth::Authentication,
        DilithiumPublicKey, 
        DilithiumSecretKey, 
        DilithiumSignature,
    },
    memory::SecureMemory,
};
use crate::auth_err;

/// Authentication Manager handles digital signatures and verification
pub struct AuthManager {
    /// Local public key for verification by the remote party
    dilithium_public_key: DilithiumPublicKey,
    
    /// Local secret key for signing (protected by SecureMemory)
    dilithium_secret_key: SecureMemory<DilithiumSecretKey>,
    
    /// Remote public key for verification
    remote_verification_key: Option<DilithiumPublicKey>,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new() -> Result<Self> {
        // Generate Dilithium key pair
        let (dilithium_public_key, dilithium_secret_key) = Authentication::generate_keypair();
        
        Ok(Self {
            dilithium_public_key,
            dilithium_secret_key: SecureMemory::new(dilithium_secret_key),
            remote_verification_key: None,
        })
    }
    
    /// Get the local verification key
    pub fn local_verification_key(&self) -> &DilithiumPublicKey {
        &self.dilithium_public_key
    }
    
    /// Set the remote verification key
    pub fn set_remote_verification_key(&mut self, key: DilithiumPublicKey) -> Result<()> {
        self.remote_verification_key = Some(key);
        Ok(())
    }
    
    /// Has the remote verification key been set?
    pub fn has_remote_verification_key(&self) -> bool {
        self.remote_verification_key.is_some()
    }
    
    /// Sign data using the local secret key
    pub fn sign(&self, data: &[u8]) -> DilithiumSignature {
        Authentication::sign(data, &*self.dilithium_secret_key)
    }
    
    /// Verify a signature using the remote verification key
    pub fn verify(&self, data: &[u8], signature: &DilithiumSignature) -> Result<()> {
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication(AuthError::MissingVerificationKey))?;
        
        Authentication::verify(data, signature, verification_key)
    }
    
    /// Get the remote verification key if available
    pub fn get_remote_verification_key(&self) -> Option<&DilithiumPublicKey> {
        self.remote_verification_key.as_ref()
    }
    
    /// Complete authentication by verifying the remote party's challenge (if needed)
    pub fn complete_authentication(&self) -> Result<()> {
        if !self.has_remote_verification_key() {
            return auth_err!(AuthError::MissingVerificationKey);
        }
        
        // At this point, we would normally verify a challenge.
        // The actual implementation would include challenge verification.
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_sign_verify() -> Result<()> {
        let alice = AuthManager::new()?;
        let bob = AuthManager::new()?;
        
        // Exchange verification keys
        alice.set_remote_verification_key(bob.local_verification_key().clone())?;
        bob.set_remote_verification_key(alice.local_verification_key().clone())?;
        
        // Alice signs a message
        let message = b"Hello, Bob!";
        let signature = alice.sign(message);
        
        // Bob verifies Alice's signature
        let result = bob.verify(message, &signature);
        assert!(result.is_ok());
        
        // Different message should fail verification
        let different_message = b"Hello, Charlie!";
        let result = bob.verify(different_message, &signature);
        assert!(result.is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_missing_verification_key() -> Result<()> {
        let alice = AuthManager::new()?;
        
        // Try to complete authentication without setting the remote verification key
        let result = alice.complete_authentication();
        assert!(result.is_err());
        
        if let Err(Error::Authentication(AuthError::MissingVerificationKey)) = result {
            // Expected error
        } else {
            panic!("Expected MissingVerificationKey error");
        }
        
        Ok(())
    }
}