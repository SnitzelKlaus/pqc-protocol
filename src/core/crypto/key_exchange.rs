/*!
Key exchange functionality for the PQC protocol.

This module provides functions for performing the key exchange phase
of the protocol using Kyber with support for different parameter sets.
*/

use crate::core::{
    constants::{sizes, HKDF_SALT, HKDF_INFO_CHACHA},
    error::{Result, Error, CryptoError},
    crypto::config::{CryptoConfig, KeyExchangeAlgorithm},
};

// Import Kyber768 (default)
use pqcrypto_kyber::{
    kyber768,
    kyber768::{
        PublicKey as Kyber768PublicKey,
        SecretKey as Kyber768SecretKey,
        Ciphertext as Kyber768Ciphertext,
        SharedSecret as Kyber768SharedSecret,
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

// Export type aliases based on the default Kyber variant
pub use pqcrypto_kyber::kyber768::{
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    Ciphertext as KyberCiphertext,
    SharedSecret as KyberSharedSecret,
};

/// KeyExchange handles the Kyber key exchange functionality
pub struct KeyExchange {
    algorithm: KeyExchangeAlgorithm,
}

impl KeyExchange {
    /// Create a new KeyExchange with the specified algorithm
    pub fn new(algorithm: KeyExchangeAlgorithm) -> Result<Self> {
        // Check if the requested algorithm is available
        match algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                // Always available as it's the default
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(not(feature = "kyber512"))]
                {
                    return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber512 is not available, enable the 'kyber512' feature".into()
                    )));
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(not(feature = "kyber1024"))]
                {
                    return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber1024 is not available, enable the 'kyber1024' feature".into()
                    )));
                }
            },
        };
        
        Ok(Self { algorithm })
    }
    
    /// Create a KeyExchange from configuration
    pub fn from_config(config: &CryptoConfig) -> Result<Self> {
        Self::new(config.key_exchange)
    }
    
    /// Get the current algorithm
    pub fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.algorithm
    }
    
    /// Generate a new Kyber key pair
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
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
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    )))
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
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Encapsulate a shared secret using the receiver's public key (sender side)
    pub fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                let pk = Kyber768PublicKey::from_bytes(public_key)
                    .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    let pk = Kyber512PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let (ss, ct) = kyber512::encapsulate(&pk);
                    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    )))
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    let pk = Kyber1024PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let (ss, ct) = kyber1024::encapsulate(&pk);
                    Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Decapsulate a shared secret from a ciphertext (receiver side)
    pub fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => {
                let ct = Kyber768Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                let sk = Kyber768SecretKey::from_bytes(secret_key)
                    .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                let ss = kyber768::decapsulate(&ct, &sk);
                Ok(ss.as_bytes().to_vec())
            },
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    let ct = Kyber512Ciphertext::from_bytes(ciphertext)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let sk = Kyber512SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let ss = kyber512::decapsulate(&ct, &sk);
                    Ok(ss.as_bytes().to_vec())
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber512 is not available".into()
                    )))
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    let ct = Kyber1024Ciphertext::from_bytes(ciphertext)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let sk = Kyber1024SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
                    let ss = kyber1024::decapsulate(&ct, &sk);
                    Ok(ss.as_bytes().to_vec())
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                        "Kyber1024 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Derive a symmetric encryption key from the shared secret
    pub fn derive_encryption_key(shared_secret: &[u8]) -> Result<[u8; sizes::chacha::KEY_SIZE]> {
        let mut okm = [0u8; sizes::chacha::KEY_SIZE];
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
        
        hkdf.expand(HKDF_INFO_CHACHA, &mut okm)
            .map_err(|_e| Error::Crypto(CryptoError::KeyDerivationFailed))?;
        
        Ok(okm)
    }
    
    /// Public key size for the configured algorithm
    pub fn public_key_size(&self) -> usize {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => sizes::kyber::PUBLIC_KEY_BYTES,
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    kyber512::public_key_bytes()
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    sizes::kyber::PUBLIC_KEY_BYTES
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    kyber1024::public_key_bytes()
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    sizes::kyber::PUBLIC_KEY_BYTES
                }
            },
        }
    }
    
    /// Ciphertext size for the configured algorithm
    pub fn ciphertext_size(&self) -> usize {
        match self.algorithm {
            KeyExchangeAlgorithm::Kyber768 => sizes::kyber::CIPHERTEXT_BYTES,
            KeyExchangeAlgorithm::Kyber512 => {
                #[cfg(feature = "kyber512")]
                {
                    kyber512::ciphertext_bytes()
                }
                #[cfg(not(feature = "kyber512"))]
                {
                    sizes::kyber::CIPHERTEXT_BYTES
                }
            },
            KeyExchangeAlgorithm::Kyber1024 => {
                #[cfg(feature = "kyber1024")]
                {
                    kyber1024::ciphertext_bytes()
                }
                #[cfg(not(feature = "kyber1024"))]
                {
                    sizes::kyber::CIPHERTEXT_BYTES
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber768_key_exchange() -> Result<()> {
        // Create key exchange with Kyber768
        let ke = KeyExchange::new(KeyExchangeAlgorithm::Kyber768)?;
        
        // Generate key pair
        let (public_key, secret_key) = ke.generate_keypair()?;
        
        // Encapsulate to get shared secret and ciphertext
        let (encap_secret, ciphertext) = ke.encapsulate(&public_key)?;
        
        // Decapsulate to get the same shared secret
        let decap_secret = ke.decapsulate(&ciphertext, &secret_key)?;
        
        // Check that the shared secrets match
        assert_eq!(encap_secret, decap_secret);
        
        Ok(())
    }
    
    #[test]
    fn test_key_derivation() -> Result<()> {
        // Generate mock shared secret
        let shared_secret = [42u8; 32];
        
        // Derive encryption key
        let key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Same input should produce same key
        let key2 = KeyExchange::derive_encryption_key(&shared_secret)?;
        assert_eq!(key, key2);
        
        // Different input should produce different key
        let different_secret = [43u8; 32];
        let key3 = KeyExchange::derive_encryption_key(&different_secret)?;
        assert_ne!(key, key3);
        
        Ok(())
    }
    
    #[test]
    fn test_public_key_size() -> Result<()> {
        let ke = KeyExchange::new(KeyExchangeAlgorithm::Kyber768)?;
        assert_eq!(ke.public_key_size(), sizes::kyber::PUBLIC_KEY_BYTES);
        
        Ok(())
    }
    
    #[cfg(feature = "kyber1024")]
    #[test]
    fn test_kyber1024_key_exchange() -> Result<()> {
        // Create key exchange with Kyber1024
        let ke = KeyExchange::new(KeyExchangeAlgorithm::Kyber1024)?;
        
        // Generate key pair
        let (public_key, secret_key) = ke.generate_keypair()?;
        
        // Encapsulate to get shared secret and ciphertext
        let (encap_secret, ciphertext) = ke.encapsulate(&public_key)?;
        
        // Decapsulate to get the same shared secret
        let decap_secret = ke.decapsulate(&ciphertext, &secret_key)?;
        
        // Check that the shared secrets match
        assert_eq!(encap_secret, decap_secret);
        
        // Key sizes should be larger for Kyber1024
        assert!(ke.public_key_size() > sizes::kyber::PUBLIC_KEY_BYTES);
        assert!(ke.ciphertext_size() > sizes::kyber::CIPHERTEXT_BYTES);
        
        Ok(())
    }
}