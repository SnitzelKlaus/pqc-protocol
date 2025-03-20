/*!
AES-256-GCM symmetric encryption implementation.

This module provides an implementation of the AES-256-GCM cipher.
*/

use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::types::algorithms::SymmetricAlgorithm;
use crate::core::crypto::types::constants::aes;
use crate::core::crypto::traits::cipher::SymmetricCipher;

#[cfg(feature = "aes-gcm")]
use aes_gcm::{
    Aes256Gcm, Key as AesKey,
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
};

/// AES-256-GCM cipher implementation
#[cfg(feature = "aes-gcm")]
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
    algorithm: SymmetricAlgorithm,
}

#[cfg(feature = "aes-gcm")]
impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher
    pub fn new(key: &[u8; aes::KEY_SIZE]) -> Self {
        Self {
            cipher: Aes256Gcm::new(AesKey::from_slice(key)),
            algorithm: SymmetricAlgorithm::Aes256Gcm,
        }
    }
}

#[cfg(feature = "aes-gcm")]
impl SymmetricCipher for Aes256GcmCipher {
    fn encrypt(&self, nonce: &chacha20poly1305::Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, data)
            .map_err(|_e| Error::EncryptionFailed)
    }
    
    fn decrypt(&self, nonce: &chacha20poly1305::Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.decrypt(nonce, data)
            .map_err(|_e| Error::DecryptionFailed)
    }
    
    fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }
    
    fn is_initialized(&self) -> bool {
        true  // If we have a Cipher instance, it's already initialized with a key
    }
}