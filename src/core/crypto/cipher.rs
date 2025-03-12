/*!
Encryption and decryption functionality for the PQC protocol.

This module provides functions for symmetric encryption and decryption
using ChaCha20-Poly1305.
*/

use crate::core::{
    constants::sizes,
    error::{Result, Error, CryptoError},
    message::types::MessageType,
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};

/// Cipher handles symmetric encryption and decryption
pub struct Cipher {
    /// The ChaCha20-Poly1305 cipher instance
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    /// Create a new Cipher with the given encryption key
    pub fn new(key: &[u8; sizes::chacha::KEY_SIZE]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }
    
    /// Encrypt data using the cipher
    pub fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::EncryptionFailed))
    }
    
    /// Decrypt data using the cipher
    pub fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::DecryptionFailed))
    }
    
    /// Create a nonce from sequence number and message type
    pub fn create_nonce(seq_num: u32, msg_type: MessageType) -> Nonce {
        let mut nonce = [0u8; sizes::chacha::NONCE_SIZE];
        
        // First 4 bytes: sequence number
        nonce[0..4].copy_from_slice(&seq_num.to_be_bytes());
        
        // 5th byte: message type
        nonce[4] = msg_type.as_u8();
        
        // Last 7 bytes: fixed data (all zeros)
        // Already initialized to zero
        
        *GenericArray::from_slice(&nonce)
    }

    /// Check if the cipher is initialized
    pub fn is_initialized(&self) -> bool {
        true  // If we have a Cipher instance, it's already initialized with a key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; sizes::chacha::KEY_SIZE];
        let cipher = Cipher::new(&key);
        
        let nonce = Cipher::create_nonce(1, MessageType::Data);
        let data = b"This is a test message";
        
        let encrypted = cipher.encrypt(&nonce, data).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();
        
        assert_eq!(data, &decrypted[..]);
        
        // Ensure different nonces produce different ciphertexts
        let nonce2 = Cipher::create_nonce(2, MessageType::Data);
        let encrypted2 = cipher.encrypt(&nonce2, data).unwrap();
        assert_ne!(encrypted, encrypted2);
    }
    
    #[test]
    fn test_create_nonce() {
        let nonce1 = Cipher::create_nonce(123, MessageType::Data);
        let nonce2 = Cipher::create_nonce(123, MessageType::Ack);
        let nonce3 = Cipher::create_nonce(456, MessageType::Data);
        
        // Same sequence number but different message types should produce different nonces
        assert_ne!(nonce1, nonce2);
        
        // Same message type but different sequence numbers should produce different nonces
        assert_ne!(nonce1, nonce3);
    }
    
    #[test]
    fn test_tampered_data() {
        let key = [0x42u8; sizes::chacha::KEY_SIZE];
        let cipher = Cipher::new(&key);
        
        let nonce = Cipher::create_nonce(1, MessageType::Data);
        let data = b"This is a test message";
        
        let mut encrypted = cipher.encrypt(&nonce, data).unwrap();
        
        // Tamper with the encrypted data
        if let Some(byte) = encrypted.get_mut(5) {
            *byte ^= 0xFF;
        }
        
        // Decryption should fail due to the authentication tag being invalid
        let result = cipher.decrypt(&nonce, &encrypted);
        assert!(result.is_err());
    }
}