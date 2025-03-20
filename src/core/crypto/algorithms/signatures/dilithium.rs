/*!
CRYSTALS-Dilithium signature implementation.

This module provides an implementation of the Dilithium signature algorithm
with support for multiple parameter sets.
*/

use crate::core::crypto::types::errors::{Result, Error, AuthError};
use crate::core::crypto::types::algorithms::SignatureAlgorithm;
use crate::core::crypto::traits::signature::Signature;

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

/// Dilithium signature implementation
pub struct DilithiumAuthenticator {
    algorithm: SignatureAlgorithm,
}

impl DilithiumAuthenticator {
    /// Create a new DilithiumAuthenticator with the specified algorithm
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
}

impl Signature for DilithiumAuthenticator {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Generate a new Dilithium key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
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
    fn sign(&self, data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
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
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
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
    fn signature_size(&self) -> usize {
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
    fn public_key_size(&self) -> usize {
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
}