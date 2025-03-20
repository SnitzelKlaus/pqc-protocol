/*!
Cryptographic algorithm configuration for the PQC protocol.

This module provides configuration options for selecting different
cryptographic algorithms at runtime, allowing greater flexibility.
*/

use crate::core::crypto::types::algorithms::{
    KeyExchangeAlgorithm,
    SignatureAlgorithm,
    SymmetricAlgorithm,
};
use crate::core::crypto::types::errors::{Result, Error};

/// Cryptographic configuration for a session
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Key exchange algorithm
    pub key_exchange: KeyExchangeAlgorithm,
    /// Signature algorithm
    pub signature: SignatureAlgorithm,
    /// Symmetric encryption algorithm
    pub symmetric: SymmetricAlgorithm,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            key_exchange: KeyExchangeAlgorithm::default(),
            signature: SignatureAlgorithm::default(),
            symmetric: SymmetricAlgorithm::default(),
        }
    }
}

impl CryptoConfig {
    /// Create a new configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create a new configuration with specific settings
    pub fn with_algorithms(
        key_exchange: KeyExchangeAlgorithm,
        signature: SignatureAlgorithm,
        symmetric: SymmetricAlgorithm,
    ) -> Self {
        Self {
            key_exchange,
            signature,
            symmetric,
        }
    }
    
    /// Create a configuration optimized for resource-constrained environments
    pub fn lightweight() -> Self {
        Self {
            key_exchange: KeyExchangeAlgorithm::Kyber512,
            signature: SignatureAlgorithm::Dilithium2,
            symmetric: SymmetricAlgorithm::ChaCha20Poly1305,
        }
    }
    
    /// Create a configuration optimized for highest security
    pub fn high_security() -> Self {
        Self {
            key_exchange: KeyExchangeAlgorithm::Kyber1024,
            signature: SignatureAlgorithm::Dilithium5,
            symmetric: SymmetricAlgorithm::ChaCha20Poly1305,
        }
    }
    
    /// Create a configuration optimized for hardware acceleration
    pub fn hardware_optimized() -> Self {
        Self {
            key_exchange: KeyExchangeAlgorithm::Kyber768,
            signature: SignatureAlgorithm::Dilithium3,
            symmetric: SymmetricAlgorithm::Aes256Gcm,
        }
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check if Kyber1024 is actually available
        #[cfg(not(feature = "kyber1024"))]
        if self.key_exchange == KeyExchangeAlgorithm::Kyber1024 {
            return Err(Error::UnsupportedAlgorithm(
                "Kyber1024 is not available, enable the 'kyber1024' feature".into()
            ));
        }
        
        // Check if Kyber512 is actually available
        #[cfg(not(feature = "kyber512"))]
        if self.key_exchange == KeyExchangeAlgorithm::Kyber512 {
            return Err(Error::UnsupportedAlgorithm(
                "Kyber512 is not available, enable the 'kyber512' feature".into()
            ));
        }
        
        // Check if Dilithium5 is actually available
        #[cfg(not(feature = "dilithium5"))]
        if self.signature == SignatureAlgorithm::Dilithium5 {
            return Err(Error::UnsupportedAlgorithm(
                "Dilithium5 is not available, enable the 'dilithium5' feature".into()
            ));
        }
        
        // Check if Dilithium2 is actually available
        #[cfg(not(feature = "dilithium2"))]
        if self.signature == SignatureAlgorithm::Dilithium2 {
            return Err(Error::UnsupportedAlgorithm(
                "Dilithium2 is not available, enable the 'dilithium2' feature".into()
            ));
        }
        
        // Check if AES-GCM is actually available
        #[cfg(not(feature = "aes-gcm"))]
        if self.symmetric == SymmetricAlgorithm::Aes256Gcm {
            return Err(Error::UnsupportedAlgorithm(
                "AES-256-GCM is not available, enable the 'aes-gcm' feature".into()
            ));
        }
        
        Ok(())
    }
    
    /// Get the name of the key exchange algorithm as a string
    pub fn key_exchange_name(&self) -> &'static str {
        self.key_exchange.name()
    }
    
    /// Get the name of the signature algorithm as a string
    pub fn signature_name(&self) -> &'static str {
        self.signature.name()
    }
    
    /// Get the name of the symmetric algorithm as a string
    pub fn symmetric_name(&self) -> &'static str {
        self.symmetric.name()
    }
}