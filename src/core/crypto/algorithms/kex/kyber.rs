/*!
CRYSTALS-Kyber key exchange implementation.

This module provides an implementation of the Kyber key exchange algorithm
with support for multiple parameter sets.
*/

use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::types::algorithms::KeyExchangeAlgorithm;
use crate::core::crypto::types::constants::{kyber, HKDF_SALT, HKDF_INFO_CHACHA};
use crate::core::crypto::traits::kex::KeyExchange;

// Import Kyber768 (default)
use pqcrypto_kyber::{
    kyber768,
    kyber768::{
        PublicKey as Kyber768PublicKey,
        SecretKey as Kyber768SecretKey,
        Ciphertext as Kyber768Ciphertext,
    }
};

// Import Kyber512 (if feature enabled)
#[cfg(feature = "kyber512")]
use pqcrypto_kyber::{
    kyber512,
    kyber512::{
        PublicKey as Kyber512PublicKey,
        SecretKey as Kyber512SecretKey,
        Ciphertext as Kyber512Ciphertext,
        SharedSecret as Kyber512SharedSecret,
    }
};

// Import Kyber1024 (if feature enabled)
#[cfg(feature = "kyber1024")]
use pqcrypto_kyber::{
    kyber1024,
    kyber1024::{
        PublicKey as Kyber1024PublicKey,
        SecretKey as Kyber1024SecretKey,
        Ciphertext as Kyber1024Ciphertext,
        SharedSecret as Kyber1024SharedSecret,
    }
};

use hkdf::Hkdf;
use sha2::Sha256;
use pqcrypto_traits::kem::SharedSecret;

/// Kyber key exchange implementation
pub struct KyberKeyExchange {
    algorithm: KeyExchangeAlgorithm,
}

impl KyberKeyExchange {
    /// Create a new KyberKeyExchange with the specified algorithm
    pub fn new(algorithm: KeyExchangeAlgorithm) -> Result<Self> {
        // Check if the requested algorithm is available
        match algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                // Always available as it's the default
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(not(feature = "kyber512"))]
                {
                    return Err(Error::UnsupportedAlgorithm(
                        "Kyber512 is not available, enable the 'kyber512' feature".into()
                    ));
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(not(feature = "kyber1024"))]
                {
                    return Err(Error::UnsupportedAlgorithm(
                        "Kyber1024 is not available, enable the 'kyber1024' feature".into()
                    ));
                }
            },
        };
        
        Ok(Self { algorithm })
    }
}

impl KeyExchange for KyberKeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.algorithm
    }

    /// Generate a new Kyber key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                let (pk, sk) = kyber768::keypair();
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    let (pk, sk) = kyber512::keypair();
                    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    ))
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    let (pk, sk) = kyber1024::keypair();
                    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    ))
                }
            },
        }
    }
    
    /// Encapsulate a shared secret using the receiver's public key (sender side)
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                let pk = Kyber768PublicKey::from_bytes(public_key)
                    .map_err(|_| Error::InvalidKeyFormat)?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    let pk = Kyber512PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let (ss, ct) = kyber512::encapsulate(&pk);
                    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    ))
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    let pk = Kyber1024PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let (ss, ct) = kyber1024::encapsulate(&pk);
                    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    ))
                }
            },
        }
    }
    
    /// Decapsulate a shared secret from a ciphertext (receiver side)
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                let ct = Kyber768Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| Error::InvalidKeyFormat)?;
                let sk = Kyber768SecretKey::from_bytes(secret_key)
                    .map_err(|_| Error::InvalidKeyFormat)?;
                let ss = kyber768::decapsulate(&ct, &sk);
                Ok(ss.as_bytes().to_vec())
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    let ct = Kyber512Ciphertext::from_bytes(ciphertext)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let sk = Kyber512SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let ss = kyber512::decapsulate(&ct, &sk);
                    Ok(ss.as_bytes().to_vec())
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    ))
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    let ct = Kyber1024Ciphertext::from_bytes(ciphertext)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let sk = Kyber1024SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::InvalidKeyFormat)?;
                    let ss = kyber1024::decapsulate(&ct, &sk);
                    Ok(ss.as_bytes().to_vec())
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    Err(Error::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    ))
                }
            },
        }
    }
    
    /// Derive a symmetric encryption key from the shared secret
    fn derive_encryption_key(&self, shared_secret: &[u8]) -> Result<[u8; 32]> {
        let mut okm = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
        
        hkdf.expand(HKDF_INFO_CHACHA, &mut okm)
            .map_err(|_e| Error::KeyDerivationFailed)?;
        
        Ok(okm)
    }
    
    /// Public key size for the configured algorithm
    fn public_key_size(&self) -> usize {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => kyber::PUBLIC_KEY_BYTES,
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    kyber512::public_key_bytes()
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    kyber::PUBLIC_KEY_BYTES
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    kyber1024::public_key_bytes()
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    kyber::PUBLIC_KEY_BYTES
                }
            },
        }
    }
    
    /// Ciphertext size for the configured algorithm
    fn ciphertext_size(&self) -> usize {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => kyber::CIPHERTEXT_BYTES,
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    kyber512::ciphertext_bytes()
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    kyber::CIPHERTEXT_BYTES
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    kyber1024::ciphertext_bytes()
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    kyber::CIPHERTEXT_BYTES
                }
            },
        }
    }
}