/*!
Key management for the PQC protocol.

This module provides functionality for key exchange, key management,
and derived key handling for the session.
*/

use crate::core::{
    error::{Result, Error},
    crypto::{
        key_exchange::KeyExchange,
        cipher::Cipher,
        KyberPublicKey,
        KyberSecretKey, 
        KyberCiphertext,
    },
    constants::sizes,
    memory::SecureMemory,
};

use pqcrypto_traits::kem::SharedSecret;

/// Key Manager handles cryptographic key management for the session
pub struct KeyManager {
    /// Kyber public key
    kyber_public_key: Option<KyberPublicKey>,
    
    /// Kyber secret key (protected by SecureMemory)
    kyber_secret_key: Option<SecureMemory<KyberSecretKey>>,
    
    /// Symmetric encryption key (protected by SecureMemory)
    encryption_key: Option<SecureMemory<[u8; sizes::chacha::KEY_SIZE]>>,
    
    /// Encryption cipher
    cipher: Option<Cipher>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            encryption_key: None,
            cipher: None,
        }
    }
    
    /// Initialize key exchange (client side)
    pub fn init_key_exchange(&mut self) -> Result<KyberPublicKey> {
        // Generate key pair
        let (public_key, secret_key) = KeyExchange::generate_keypair();
        
        // Store keys, wrapping the secret key in SecureMemory
        self.kyber_public_key = Some(public_key.clone());
        self.kyber_secret_key = Some(SecureMemory::new(secret_key));
        
        Ok(public_key)
    }
    
    /// Accept key exchange (server side)
    pub fn accept_key_exchange(&mut self, client_public_key: &KyberPublicKey) -> Result<KyberCiphertext> {
        // Encapsulate shared secret
        let (shared_secret, ciphertext) = KeyExchange::encapsulate(client_public_key);
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(shared_secret.as_bytes())
            .map_err(|e| e)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
        self.cipher = Some(Cipher::new(&*self.encryption_key.as_ref().unwrap()));
        
        Ok(ciphertext)
    }
    
    /// Process key exchange response (client side)
    pub fn process_key_exchange(&mut self, ciphertext: &KyberCiphertext) -> Result<()> {
        let secure_kyber_secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Secret key not available".into()))?;
        
        // Decapsulate shared secret using the underlying key from SecureMemory
        let shared_secret = KeyExchange::decapsulate(ciphertext, &*secure_kyber_secret_key);
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(shared_secret.as_bytes())
            .map_err(|e| e)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
        self.cipher = Some(Cipher::new(&*self.encryption_key.as_ref().unwrap()));
        
        Ok(())
    }
    
    /// Get the current Kyber public key (if available)
    pub fn get_public_key(&self) -> Option<&KyberPublicKey> {
        self.kyber_public_key.as_ref()
    }
    
    /// Get access to the cipher for encryption/decryption operations
    pub fn get_cipher(&self) -> Result<&Cipher> {
        self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Get access to the cipher for encryption/decryption operations (mutable)
    pub fn get_cipher_mut(&mut self) -> Result<&mut Cipher> {
        self.cipher.as_mut()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Clear sensitive keys (useful during key rotation)
    pub fn clear_keys(&mut self) {
        self.kyber_public_key = None;
        self.kyber_secret_key = None;
        // Note: We don't clear encryption_key and cipher 
        // as they're needed until new ones are established
    }
    
    /// Update the encryption key and cipher
    pub fn update_encryption(&mut self, new_encryption_key: [u8; sizes::chacha::KEY_SIZE]) -> Result<()> {
        self.encryption_key = Some(SecureMemory::new(new_encryption_key));
        self.cipher = Some(Cipher::new(&*self.encryption_key.as_ref().unwrap()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_exchange() -> Result<()> {
        let mut client_key_manager = KeyManager::new();
        let mut server_key_manager = KeyManager::new();
        
        // Client initiates key exchange
        let client_public_key = client_key_manager.init_key_exchange()?;
        
        // Server accepts key exchange
        let ciphertext = server_key_manager.accept_key_exchange(&client_public_key)?;
        
        // Client processes server's response
        client_key_manager.process_key_exchange(&ciphertext)?;
        
        // Verify both sides have initialized the cipher
        let client_cipher = client_key_manager.get_cipher()?;
        let server_cipher = server_key_manager.get_cipher()?;
        
        assert!(client_cipher.is_initialized());
        assert!(server_cipher.is_initialized());
        
        Ok(())
    }
}