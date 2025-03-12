/*!
Encryption and decryption functionality for the PQC protocol.

This module provides functions for symmetric encryption and decryption
with support for multiple algorithms.
*/

use crate::core::{
    constants::sizes,
    error::{Result, Error, CryptoError},
    message::types::MessageType,
    crypto::config::{CryptoConfig, SymmetricAlgorithm},
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key as ChaChaKey, Nonce,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};

#[cfg(feature = "aes-gcm")]
use aes_gcm::{
    Aes256Gcm, Key as AesKey,
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
};

/// Trait for symmetric cipher operations
pub trait SymmetricCipher: Send + Sync {
    /// Encrypt data with the cipher
    fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data with the cipher
    fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>>;
}

/// ChaCha20-Poly1305 cipher implementation
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher
    pub fn new(key: &[u8; sizes::chacha::KEY_SIZE]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(ChaChaKey::from_slice(key)),
        }
    }
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::EncryptionFailed))
    }
    
    fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::DecryptionFailed))
    }
}

/// AES-256-GCM cipher implementation
#[cfg(feature = "aes-gcm")]
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

#[cfg(feature = "aes-gcm")]
impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher
    pub fn new(key: &[u8; sizes::aes::KEY_SIZE]) -> Self {
        Self {
            cipher: Aes256Gcm::new(AesKey::from_slice(key)),
        }
    }
}

#[cfg(feature = "aes-gcm")]
impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::EncryptionFailed))
    }
    
    fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(nonce, data)
            .map_err(|_e| Error::Crypto(CryptoError::DecryptionFailed))
    }
}

/// Unified cipher handler that supports multiple symmetric algorithms
pub struct Cipher {
    /// The inner cipher implementation
    inner: Box<dyn SymmetricCipher>,
    /// The algorithm being used
    algorithm: SymmetricAlgorithm,
}

impl Cipher {
    /// Create a new Cipher with the given encryption key and algorithm
    pub fn new(key: &[u8; 32], algorithm: SymmetricAlgorithm) -> Result<Self> {
        let inner: Box<dyn SymmetricCipher> = match algorithm {
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                Box::new(ChaCha20Poly1305Cipher::new(key))
            },
            SymmetricAlgorithm::Aes256Gcm => {
                #[cfg(feature = "aes-gcm")]
                {
                    Box::new(Aes256GcmCipher::new(key))
                }
                #[cfg(not(feature = "aes-gcm"))]
                {
                    return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "AES-256-GCM is not available, enable the 'aes-gcm' feature".into()
                    )));
                }
            },
        };
        
        Ok(Self {
            inner,
            algorithm,
        })
    }
    
    /// Create a cipher from configuration
    pub fn from_config(key: &[u8; 32], config: &CryptoConfig) -> Result<Self> {
        Self::new(key, config.symmetric)
    }
    
    /// Encrypt data using the cipher
    pub fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(nonce, data)
    }
    
    /// Decrypt data using the cipher
    pub fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(nonce, data)
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
    
    /// Get the algorithm being used
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chacha20poly1305() {
        let key = [0x42u8; sizes::chacha::KEY_SIZE];
        let config = CryptoConfig::default(); // Uses ChaCha20Poly1305 by default
        let cipher = Cipher::from_config(&key, &config).unwrap();
        
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
    
    #[cfg(feature = "aes-gcm")]
    #[test]
    fn test_aes256gcm() {
        let key = [0x42u8; sizes::chacha::KEY_SIZE];
        let config = CryptoConfig::with_algorithms(
            KeyExchangeAlgorithm::Kyber768,
            SignatureAlgorithm::Dilithium3,
            SymmetricAlgorithm::Aes256Gcm,
        );
        let cipher = Cipher::from_config(&key, &config).unwrap();
        
        let nonce = Cipher::create_nonce(1, MessageType::Data);
        let data = b"This is a test message";
        
        let encrypted = cipher.encrypt(&nonce, data).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted).unwrap();
        
        assert_eq!(data, &decrypted[..]);
        assert_eq!(cipher.algorithm(), SymmetricAlgorithm::Aes256Gcm);
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
        let config = CryptoConfig::default();
        let cipher = Cipher::from_config(&key, &config).unwrap();
        
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