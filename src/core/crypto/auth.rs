/*!
Authentication functionality for the PQC protocol.

This module provides functions for digital signatures and verification
using Dilithium with support for multiple parameter sets.
*/

use crate::core::error::{Result, Error, AuthError};
use crate::core::crypto::config::{CryptoConfig, SignatureAlgorithm};
use crate::auth_err;

// Import Dilithium3 (default)
use pqcrypto_dilithium::{
    dilithium3,
    dilithium3::{
        PublicKey as Dilithium3PublicKey,
        SecretKey as Dilithium3SecretKey,
        DetachedSignature as Dilithium3Signature,
    },
};

// Import Dilithium2 (if feature enabled)
#[cfg(feature = "dilithium2")]
use pqcrypto_dilithium::{
    dilithium2,
    dilithium2::{
        PublicKey as Dilithium2PublicKey,
        SecretKey as Dilithium2SecretKey,
        DetachedSignature as Dilithium2Signature,
    },
};

// Import Dilithium5 (if feature enabled)
#[cfg(feature = "dilithium5")]
use pqcrypto_dilithium::{
    dilithium5,
    dilithium5::{
        PublicKey as Dilithium5PublicKey,
        SecretKey as Dilithium5SecretKey,
        DetachedSignature as Dilithium5Signature,
    },
};

use pqcrypto_traits::sign::DetachedSignature;

// Export type aliases based on the default Dilithium variant
pub use pqcrypto_dilithium::dilithium3::{
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    DetachedSignature as DilithiumSignature,
};

/// Authentication handler for digital signatures
pub struct Authentication {
    algorithm: SignatureAlgorithm,
}

impl Authentication {
    /// Create a new Authentication instance with the specified algorithm
    pub fn new(algorithm: SignatureAlgorithm) -> Result<Self> {
        // Check if the requested algorithm is available
        match algorithm {
            SignatureAlgorithm::Dilithium3 => {
                // Always available as it's the default
            },
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(not(feature = "dilithium2"))]
                {
                    return Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium2 is not available, enable the 'dilithium2' feature".into()
                    )));
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(not(feature = "dilithium5"))]
                {
                    return Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium5 is not available, enable the 'dilithium5' feature".into()
                    )));
                }
            },
        };
        
        Ok(Self { algorithm })
    }
    
    /// Create an Authentication from configuration
    pub fn from_config(config: &CryptoConfig) -> Result<Self> {
        Self::new(config.signature)
    }
    
    /// Generate a new Dilithium key pair
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.algorithm {
            SignatureAlgorithm::Dilithium3 => {
                let (pk, sk) = dilithium3::keypair();
                Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
            },
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(feature = "dilithium2")]
                {
                    let (pk, sk) = dilithium2::keypair();
                    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "dilithium2"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium2 is not available".into()
                    )))
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(feature = "dilithium5")]
                {
                    let (pk, sk) = dilithium5::keypair();
                    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
                }
                #[cfg(not(feature = "dilithium5"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium5 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Sign data using a Dilithium signing key
    pub fn sign(&self, data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            SignatureAlgorithm::Dilithium3 => {
                let sk = Dilithium3SecretKey::from_bytes(secret_key)
                    .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                let signature = dilithium3::detached_sign(data, &sk);
                Ok(signature.as_bytes().to_vec())
            },
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(feature = "dilithium2")]
                {
                    let sk = Dilithium2SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                    let signature = dilithium2::detached_sign(data, &sk);
                    Ok(signature.as_bytes().to_vec())
                }
                #[cfg(not(feature = "dilithium2"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium2 is not available".into()
                    )))
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(feature = "dilithium5")]
                {
                    let sk = Dilithium5SecretKey::from_bytes(secret_key)
                        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                    let signature = dilithium5::detached_sign(data, &sk);
                    Ok(signature.as_bytes().to_vec())
                }
                #[cfg(not(feature = "dilithium5"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium5 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Verify a signature using a Dilithium verification key
    pub fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        match self.algorithm {
            SignatureAlgorithm::Dilithium3 => {
                let pk = Dilithium3PublicKey::from_bytes(public_key)
                    .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                let sig = Dilithium3Signature::from_bytes(signature)
                    .map_err(|_| Error::Authentication(AuthError::InvalidSignatureFormat))?;
                    
                match dilithium3::verify_detached_signature(&sig, data, &pk) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(Error::Authentication(AuthError::SignatureVerificationFailed)),
                }
            },
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(feature = "dilithium2")]
                {
                    let pk = Dilithium2PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                    let sig = Dilithium2Signature::from_bytes(signature)
                        .map_err(|_| Error::Authentication(AuthError::InvalidSignatureFormat))?;
                        
                    match dilithium2::verify_detached_signature(&sig, data, &pk) {
                        Ok(_) => Ok(()),
                        Err(_) => Err(Error::Authentication(AuthError::SignatureVerificationFailed)),
                    }
                }
                #[cfg(not(feature = "dilithium2"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium2 is not available".into()
                    )))
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(feature = "dilithium5")]
                {
                    let pk = Dilithium5PublicKey::from_bytes(public_key)
                        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
                    let sig = Dilithium5Signature::from_bytes(signature)
                        .map_err(|_| Error::Authentication(AuthError::InvalidSignatureFormat))?;
                        
                    match dilithium5::verify_detached_signature(&sig, data, &pk) {
                        Ok(_) => Ok(()),
                        Err(_) => Err(Error::Authentication(AuthError::SignatureVerificationFailed)),
                    }
                }
                #[cfg(not(feature = "dilithium5"))]
                {
                    Err(Error::Authentication(AuthError::UnsupportedAlgorithm(
                        "Dilithium5 is not available".into()
                    )))
                }
            },
        }
    }
    
    /// Get the signature size for the configured algorithm
    pub fn signature_size(&self) -> usize {
        match self.algorithm {
            SignatureAlgorithm::Dilithium3 => dilithium3::signature_bytes(),
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(feature = "dilithium2")]
                {
                    dilithium2::signature_bytes()
                }
                #[cfg(not(feature = "dilithium2"))]
                {
                    dilithium3::signature_bytes() // Default fallback
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(feature = "dilithium5")]
                {
                    dilithium5::signature_bytes()
                }
                #[cfg(not(feature = "dilithium5"))]
                {
                    dilithium3::signature_bytes() // Default fallback
                }
            },
        }
    }
    
    /// Get the public key size for the configured algorithm
    pub fn public_key_size(&self) -> usize {
        match self.algorithm {
            SignatureAlgorithm::Dilithium3 => dilithium3::public_key_bytes(),
            SignatureAlgorithm::Dilithium2 => {
                #[cfg(feature = "dilithium2")]
                {
                    dilithium2::public_key_bytes()
                }
                #[cfg(not(feature = "dilithium2"))]
                {
                    dilithium3::public_key_bytes() // Default fallback
                }
            },
            SignatureAlgorithm::Dilithium5 => {
                #[cfg(feature = "dilithium5")]
                {
                    dilithium5::public_key_bytes()
                }
                #[cfg(not(feature = "dilithium5"))]
                {
                    dilithium3::public_key_bytes() // Default fallback
                }
            },
        }
    }
    
    /// Get the algorithm being used
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// Add the UnsupportedAlgorithm error type to AuthError
impl AuthError {
    /// Create an UnsupportedAlgorithm error
    pub fn unsupported_algorithm(msg: &str) -> Self {
        AuthError::UnsupportedAlgorithm(msg.to_string())
    }
}

// Update AuthError to include the new error type
#[derive(Error, Debug)]
pub enum AuthError {
    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    /// Missing verification key
    #[error("Verification key not available")]
    MissingVerificationKey,
    
    /// Invalid key format
    #[error("Invalid key format")]
    InvalidKeyFormat,
    
    /// Invalid signature format
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    
    /// Authentication timeout
    #[error("Authentication timed out")]
    Timeout,
    
    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dilithium3_signature_verification() -> Result<()> {
        let config = CryptoConfig::default();
        let auth = Authentication::from_config(&config)?;
        
        let (public_key, secret_key) = auth.generate_keypair()?;
        let data = b"This is a test message to sign";
        
        let signature = auth.sign(data, &secret_key)?;
        let result = auth.verify(data, &signature, &public_key);
        
        assert!(result.is_ok());
        
        Ok(())
    }
    
    #[test]
    fn test_invalid_signature() -> Result<()> {
        let config = CryptoConfig::default();
        let auth = Authentication::from_config(&config)?;
        
        let (public_key, secret_key) = auth.generate_keypair()?;
        let data = b"This is a test message to sign";
        let different_data = b"This is a different message";
        
        let signature = auth.sign(data, &secret_key)?;
        
        // Signature should not verify for different data
        let result = auth.verify(different_data, &signature, &public_key);
        assert!(result.is_err());
        
        Ok(())
    }
    
    #[test]
    fn test_tampered_signature() -> Result<()> {
        let config = CryptoConfig::default();
        let auth = Authentication::from_config(&config)?;
        
        let (public_key, secret_key) = auth.generate_keypair()?;
        let data = b"This is a test message to sign";
        
        let mut signature = auth.sign(data, &secret_key)?;
        
        // Tamper with the signature
        if let Some(byte) = signature.get_mut(signature.len() / 2) {
            *byte ^= 0xFF;
        }
        
        // Tampered signature should not verify
        let result = auth.verify(data, &signature, &public_key);
        assert!(result.is_err());
        
        Ok(())
    }
    
    #[cfg(feature = "dilithium5")]
    #[test]
    fn test_dilithium5_signature() -> Result<()> {
        let config = CryptoConfig::with_algorithms(
            KeyExchangeAlgorithm::Kyber768,
            SignatureAlgorithm::Dilithium5,
            SymmetricAlgorithm::ChaCha20Poly1305,
        );
        let auth = Authentication::from_config(&config)?;
        
        let (public_key, secret_key) = auth.generate_keypair()?;
        let data = b"This is a test message to sign with Dilithium5";
        
        let signature = auth.sign(data, &secret_key)?;
        let result = auth.verify(data, &signature, &public_key);
        
        assert!(result.is_ok());
        
        // Dilithium5 signatures should be larger than Dilithium3
        let d3_auth = Authentication::new(SignatureAlgorithm::Dilithium3)?;
        assert!(auth.signature_size() > d3_auth.signature_size());
        
        Ok(())
    }
}