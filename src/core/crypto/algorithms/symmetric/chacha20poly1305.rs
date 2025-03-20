/*!
ChaCha20-Poly1305 symmetric encryption implementation.

This module provides an implementation of the ChaCha20-Poly1305 cipher.
*/

use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::types::algorithms::SymmetricAlgorithm;
use crate::core::crypto::types::constants::chacha;
use crate::core::crypto::traits::cipher::SymmetricCipher;

use chacha20poly1305::{
    ChaCha20Poly1305, Key as ChaChaKey, Nonce,
    aead::{Aead, KeyInit},
};

/// ChaCha20-Poly1305 cipher implementation
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
    algorithm: SymmetricAlgorithm,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher
    pub fn new(key: &[u8; chacha::KEY_SIZE]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(ChaChaKey::from_slice(key)),
            algorithm: SymmetricAlgorithm::ChaCha20Poly1305,
        }
    }
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
        self.cipher.encrypt(nonce, data)
            .map_err(|_e| Error::EncryptionFailed)
    }
    
    fn decrypt(&self, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>> {
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