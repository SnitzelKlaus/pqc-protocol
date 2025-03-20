/*!
Key exchange algorithm implementations.

This module provides implementations of key exchange algorithms.
*/

mod kyber;

use crate::core::crypto::types::algorithms::KeyExchangeAlgorithm;
use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::traits::kex::KeyExchange;

// Re-export Kyber types
pub use pqcrypto_kyber::kyber768::{
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    Ciphertext as KyberCiphertext,
    SharedSecret as KyberSharedSecret,
};

/// Create a key exchange implementation for the specified algorithm
pub fn create_key_exchange(algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn KeyExchange>> {
    match algorithm {
        KeyExchangeAlgorithm::Kyber768 => {
            Ok(Box::new(kyber::KyberKeyExchange::new(algorithm)?))
        },
        KeyExchangeAlgorithm::Kyber512 => {
            #[cfg(feature = "kyber512")]
            {
                Ok(Box::new(kyber::KyberKeyExchange::new(algorithm)?))
            }
            #[cfg(not(feature = "kyber512"))]
            {
                Err(Error::UnsupportedAlgorithm(
                    "Kyber512 is not available, enable the 'kyber512' feature".into()
                ))
            }
        },
        KeyExchangeAlgorithm::Kyber1024 => {
            #[cfg(feature = "kyber1024")]
            {
                Ok(Box::new(kyber::KyberKeyExchange::new(algorithm)?))
            }
            #[cfg(not(feature = "kyber1024"))]
            {
                Err(Error::UnsupportedAlgorithm(
                    "Kyber1024 is not available, enable the 'kyber1024' feature".into()
                ))
            }
        },
    }
}