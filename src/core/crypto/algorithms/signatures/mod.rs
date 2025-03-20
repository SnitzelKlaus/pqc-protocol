/*!
Signature algorithm implementations.

This module provides implementations of signature algorithms.
*/

mod dilithium;

use crate::core::crypto::types::algorithms::SignatureAlgorithm;
use crate::core::crypto::types::errors::{Result, Error};
use crate::core::crypto::traits::signature::Signature;

// Re-export Dilithium types
pub use pqcrypto_dilithium::dilithium3::{
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    DetachedSignature as DilithiumSignature,
};

/// Create an authenticator for the specified algorithm
pub fn create_authenticator(algorithm: SignatureAlgorithm) -> Result<Box<dyn Signature>> {
    match algorithm {
        SignatureAlgorithm::Dilithium3 => {
            Ok(Box::new(dilithium::DilithiumAuthenticator::new(algorithm)?))
        },
        SignatureAlgorithm::Dilithium2 => {
            #[cfg(feature = "dilithium2")]
            {
                Ok(Box::new(dilithium::DilithiumAuthenticator::new(algorithm)?))
            }
            #[cfg(not(feature = "dilithium2"))]
            {
                Err(Error::UnsupportedAlgorithm(
                    "Dilithium2 is not available, enable the 'dilithium2' feature".into()
                ))
            }
        },
        SignatureAlgorithm::Dilithium5 => {
            #[cfg(feature = "dilithium5")]
            {
                Ok(Box::new(dilithium::DilithiumAuthenticator::new(algorithm)?))
            }
            #[cfg(not(feature = "dilithium5"))]
            {
                Err(Error::UnsupportedAlgorithm(
                    "Dilithium5 is not available, enable the 'dilithium5' feature".into()
                ))
            }
        },
    }
}