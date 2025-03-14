/*!
Enhanced authentication management for the PQC protocol.

This module provides functionality for handling the authentication phase
of the protocol, including signature generation and verification with
support for multiple signature algorithms.
*/

use crate::core::{
    error::{Result, Error, AuthError},
    crypto::{
        auth::Authentication,
        config::{CryptoConfig, SignatureAlgorithm},
        DilithiumPublicKey, 
        DilithiumSignature,
    },
    memory::{SecureMemory, SecureVec, Zeroize},
};
use crate::auth_err;

/// Authentication Manager handles digital signatures and verification
pub struct AuthManager {
    /// Local public key for verification by the remote party
    public_key: Vec<u8>,
    
    /// Local secret key for signing (protected by SecureMemory)
    secret_key: SecureMemory<Vec<u8>>,
    
    /// Remote public key for verification
    remote_verification_key: Option<DilithiumPublicKey>,
    
    /// Current signature algorithm
    signature_algorithm: SignatureAlgorithm,
    
    /// Authentication handler
    auth: Authentication,
}

impl AuthManager {
    /// Create a new authentication manager with default algorithm
    pub fn new() -> Result<Self> {
        Self::new_with_config(&CryptoConfig::default())
    }
    
    /// Create a new authentication manager with specified algorithm
    pub fn new_with_config(config: &CryptoConfig) -> Result<Self> {
        // Create authentication handler
        let auth = Authentication::new(config.signature)?;
        
        // Generate key pair
        let (public_key, secret_key) = auth.generate_keypair()?;
        
        // For backward compatibility, convert the public key to DilithiumPublicKey
        let dilithium_public_key = DilithiumPublicKey::from_bytes(&public_key)?;
        
        Ok(Self {
            public_key,
            secret_key: SecureMemory::new(secret_key),
            remote_verification_key: None,
            signature_algorithm: config.signature,
            auth,
        })
    }
    
    /// Get the current signature algorithm
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
    
    /// Get the local verification key
    pub fn local_verification_key(&self) -> &DilithiumPublicKey {
        // This assumes we've verified this is a valid DilithiumPublicKey during initialization
        // In a more robust implementation, we might store both the raw bytes and the parsed key
        if let Ok(pk) = DilithiumPublicKey::from_bytes(&self.public_key) {
            return &pk;
        }
        
        // This should never happen as we verified during initialization
        panic!("Invalid local verification key");
    }
    
    /// Get the local verification key as raw bytes
    pub fn local_verification_key_bytes(&self) -> &[u8] {
        &self.public_key
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
    pub fn sign(&self, data: &[u8]) -> Result<DilithiumSignature> {
        // Sign the data using the appropriate algorithm
        let signature_bytes = self.auth.sign(data, &self.secret_key)?;
        
        // Convert to DilithiumSignature for backward compatibility
        let signature = DilithiumSignature::from_bytes(&signature_bytes)?;
        Ok(signature)
    }
    
    /// Verify a signature using the remote verification key
    pub fn verify(&self, data: &[u8], signature: &DilithiumSignature) -> Result<()> {
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication(AuthError::MissingVerificationKey))?;
        
        // Convert to bytes for verification with our authentication handler
        let signature_bytes = signature.as_bytes();
        let verification_key_bytes = verification_key.as_bytes();
        
        // Verify the signature
        self.auth.verify(data, signature_bytes, verification_key_bytes)
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
        // This is a placeholder for challenge-response verification.
        
        Ok(())
    }
    
    /// Update the key pair with a new algorithm
    pub fn update_key_pair(&mut self, algorithm: SignatureAlgorithm) -> Result<()> {
        // Create a new authentication handler
        let auth = Authentication::new(algorithm)?;
        
        // Generate a new key pair
        let (public_key, secret_key) = auth.generate_keypair()?;
        
        // Update the manager
        self.public_key = public_key;
        self.secret_key = SecureMemory::new(secret_key);
        self.signature_algorithm = algorithm;
        self.auth = auth;
        
        Ok(())
    }
    
    /// Get the signature size for the current algorithm
    pub fn signature_size(&self) -> usize {
        self.auth.signature_size()
    }
    
    /// Create a signature from bytes
    pub fn signature_from_bytes(&self, bytes: &[u8]) -> Result<DilithiumSignature> {
        DilithiumSignature::from_bytes(bytes)
            .map_err(|_| Error::Authentication(AuthError::InvalidSignatureFormat))
    }
    
    /// Zeroize sensitive data
    pub fn zeroize_sensitive_data(&mut self) {
        // Zeroize the secret key
        self.secret_key.zeroize();
    }
}

// Implement Zeroize trait for AuthManager
impl Zeroize for AuthManager {
    fn zeroize(&mut self) {
        self.zeroize_sensitive_data();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_sign_verify() -> Result<()> {
        let config = CryptoConfig::default();
        let mut alice = AuthManager::new_with_config(&config)?;
        let mut bob = AuthManager::new_with_config(&config)?;
        
        // Exchange verification keys
        let alice_pubkey = DilithiumPublicKey::from_bytes(alice.local_verification_key_bytes())?;
        let bob_pubkey = DilithiumPublicKey::from_bytes(bob.local_verification_key_bytes())?;
        
        alice.set_remote_verification_key(bob_pubkey)?;
        bob.set_remote_verification_key(alice_pubkey)?;
        
        // Alice signs a message
        let message = b"Hello, Bob!";
        let signature = alice.sign(message)?;
        
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
    
    #[test]
    fn test_algorithm_update() -> Result<()> {
        let mut auth_manager = AuthManager::new()?;
        
        // Check initial algorithm
        assert_eq!(auth_manager.signature_algorithm(), SignatureAlgorithm::default());
        
        // Update to a different algorithm (if supported)
        #[cfg(feature = "dilithium5")]
        {
            auth_manager.update_key_pair(SignatureAlgorithm::Dilithium5)?;
            assert_eq!(auth_manager.signature_algorithm(), SignatureAlgorithm::Dilithium5);
            
            // Signature size should be larger for Dilithium5
            let dilithium3_size = Authentication::new(SignatureAlgorithm::Dilithium3)?.signature_size();
            assert!(auth_manager.signature_size() > dilithium3_size);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_different_configs() -> Result<()> {
        // Test with high security config
        let high_sec_config = CryptoConfig::high_security();
        let mut alice = AuthManager::new_with_config(&high_sec_config)?;
        let mut bob = AuthManager::new_with_config(&high_sec_config)?;
        
        // Exchange verification keys
        let alice_pubkey = DilithiumPublicKey::from_bytes(alice.local_verification_key_bytes())?;
        let bob_pubkey = DilithiumPublicKey::from_bytes(bob.local_verification_key_bytes())?;
        
        alice.set_remote_verification_key(bob_pubkey)?;
        bob.set_remote_verification_key(alice_pubkey)?;
        
        // Alice signs a message
        let message = b"High security message";
        let signature = alice.sign(message)?;
        
        // Bob verifies Alice's signature
        let result = bob.verify(message, &signature);
        assert!(result.is_ok());
        
        // Check algorithm is as expected
        assert_eq!(alice.signature_algorithm(), high_sec_config.signature);
        
        Ok(())
    }
    
    #[test]
    fn test_zeroize() -> Result<()> {
        let mut auth_manager = AuthManager::new()?;
        
        // Test zeroization
        auth_manager.zeroize();
        
        // Secret key should be zeroed but still in a valid state
        assert!(auth_manager.sign(b"Test").is_ok());
        
        Ok(())
    }
}