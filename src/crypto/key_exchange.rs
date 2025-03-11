/*!
Key exchange functionality for the PQC protocol.

This module provides functions for performing the key exchange phase
of the protocol using Kyber.
*/

use crate::{
    constants::{sizes, HKDF_SALT, HKDF_INFO_CHACHA},
    error::{Result, Error},
};

use pqcrypto_kyber::{
    kyber768,
    kyber768::{
        PublicKey as KyberPublicKey,
        SecretKey as KyberSecretKey,
        Ciphertext as KyberCiphertext,
        SharedSecret as KyberSharedSecret,
    }
};

use hkdf::Hkdf;
use sha2::Sha256;

/// KeyExchange handles the Kyber key exchange functionality
pub struct KeyExchange;

impl KeyExchange {
    /// Generate a new Kyber key pair
    pub fn generate_keypair() -> (KyberPublicKey, KyberSecretKey) {
        kyber768::keypair()
    }
    
    /// Encapsulate a shared secret using the receiver's public key (sender side)
    pub fn encapsulate(public_key: &KyberPublicKey) -> (KyberSharedSecret, KyberCiphertext) {
        kyber768::encapsulate(public_key)
    }
    
    /// Decapsulate a shared secret from a ciphertext (receiver side)
    pub fn decapsulate(ciphertext: &KyberCiphertext, secret_key: &KyberSecretKey) -> KyberSharedSecret {
        kyber768::decapsulate(ciphertext, secret_key)
    }
    
    /// Derive a symmetric encryption key from the shared secret
    pub fn derive_encryption_key(shared_secret: &[u8]) -> Result<[u8; sizes::chacha::KEY_SIZE]> {
        let mut okm = [0u8; sizes::chacha::KEY_SIZE];
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
        
        hkdf.expand(HKDF_INFO_CHACHA, &mut okm)
            .map_err(|e| Error::Crypto(format!("HKDF key derivation failed: {}", e)))?;
        
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pqcrypto_traits::kem::SharedSecret;
    
    #[test]
    fn test_kyber_key_exchange() {
        // Generate key pair
        let (public_key, secret_key) = KeyExchange::generate_keypair();
        
        // Encapsulate to get shared secret and ciphertext
        let (encap_secret, ciphertext) = KeyExchange::encapsulate(&public_key);
        
        // Decapsulate to get the same shared secret
        let decap_secret = KeyExchange::decapsulate(&ciphertext, &secret_key);
        
        // Check that the shared secrets match by calling the `.as_bytes()` method:
        assert_eq!(encap_secret.as_bytes(), decap_secret.as_bytes());
    }
    
    #[test]
    fn test_key_derivation() {
        // Generate mock shared secret
        let shared_secret = [42u8; 32];
        
        // Derive encryption key
        let key = KeyExchange::derive_encryption_key(&shared_secret).unwrap();
        
        // Same input should produce same key
        let key2 = KeyExchange::derive_encryption_key(&shared_secret).unwrap();
        assert_eq!(key, key2);
        
        // Different input should produce different key
        let different_secret = [43u8; 32];
        let key3 = KeyExchange::derive_encryption_key(&different_secret).unwrap();
        assert_ne!(key, key3);
    }
}