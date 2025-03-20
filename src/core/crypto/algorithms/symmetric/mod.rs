/*!
Symmetric encryption algorithm implementations.

This module provides implementations of symmetric encryption algorithms.
*/

mod chacha20poly1305;
#[cfg(feature = "aes-gcm")]
mod aes_gcm;

use crate::core::crypto::types::algorithms::SymmetricAlgorithm;
use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::traits::cipher::SymmetricCipher;

/// Create a cipher for the specified algorithm
pub fn create_cipher(key: &[u8; 32], algorithm: SymmetricAlgorithm) -> Result<Box<dyn SymmetricCipher>> {
    match algorithm {
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            Ok(Box::new(chacha20poly1305::ChaCha20Poly1305Cipher::new(key)))
        },
        SymmetricAlgorithm::Aes256Gcm => {
            #[cfg(feature = "aes-gcm")]
            {
                Ok(Box::new(aes_gcm::Aes256GcmCipher::new(key)))
            }
            #[cfg(not(feature = "aes-gcm"))]
            {
                Err(Error::UnsupportedAlgorithm(
                    "AES-256-GCM is not available, enable the 'aes-gcm' feature".into()
                ))
            }
        },
    }
}