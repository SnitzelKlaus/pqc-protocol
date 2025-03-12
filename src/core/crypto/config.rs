/*!
Cryptographic algorithm configuration for the PQC protocol.

This module provides configuration options for selecting different
cryptographic algorithms at runtime, allowing greater flexibility.
*/

use crate::core::error::{Result, Error, CryptoError};

/// Supported Key Exchange Mechanisms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    /// CRYSTALS-Kyber KEM (Kyber768)
    Kyber768,
    /// CRYSTALS-Kyber KEM (Kyber512) - for resource-constrained environments
    Kyber512,
    /// CRYSTALS-Kyber KEM (Kyber1024) - highest security level
    Kyber1024,
}

impl Default for KeyExchangeAlgorithm {
    fn default() -> Self {
        KeyExchangeAlgorithm::Kyber768
    }
}

/// Supported Digital Signature Algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// CRYSTALS-Dilithium (dilithium3)
    Dilithium3,
    /// CRYSTALS-Dilithium (dilithium2) - for resource-constrained environments
    Dilithium2,
    /// CRYSTALS-Dilithium (dilithium5) - highest security level
    Dilithium5,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm::Dilithium3
    }
}

/// Supported Symmetric Encryption Algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricAlgorithm {
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// AES-256-GCM - hardware acceleration on many platforms
    Aes256Gcm,
}

impl Default for SymmetricAlgorithm {
    fn default() -> Self {
        SymmetricAlgorithm::ChaCha20Poly1305
    }
}

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
            return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                "Kyber1024 is not available, enable the 'kyber1024' feature".into()
            )));
        }
        
        // Check if Kyber512 is actually available
        #[cfg(not(feature = "kyber512"))]
        if self.key_exchange == KeyExchangeAlgorithm::Kyber512 {
            return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                "Kyber512 is not available, enable the 'kyber512' feature".into()
            )));
        }
        
        // Check if Dilithium5 is actually available
        #[cfg(not(feature = "dilithium5"))]
        if self.signature == SignatureAlgorithm::Dilithium5 {
            return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                "Dilithium5 is not available, enable the 'dilithium5' feature".into()
            )));
        }
        
        // Check if Dilithium2 is actually available
        #[cfg(not(feature = "dilithium2"))]
        if self.signature == SignatureAlgorithm::Dilithium2 {
            return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                "Dilithium2 is not available, enable the 'dilithium2' feature".into()
            )));
        }
        
        // Check if AES-GCM is actually available
        #[cfg(not(feature = "aes-gcm"))]
        if self.symmetric == SymmetricAlgorithm::Aes256Gcm {
            return Err(Error::Crypto(CryptoError::UnsupportedAlgorithm(
                "AES-256-GCM is not available, enable the 'aes-gcm' feature".into()
            )));
        }
        
        Ok(())
    }
    
    /// Get the name of the key exchange algorithm as a string
    pub fn key_exchange_name(&self) -> &'static str {
        match self.key_exchange {
            KeyExchangeAlgorithm::Kyber768 => "CRYSTALS-Kyber-768",
            KeyExchangeAlgorithm::Kyber512 => "CRYSTALS-Kyber-512",
            KeyExchangeAlgorithm::Kyber1024 => "CRYSTALS-Kyber-1024",
        }
    }
    
    /// Get the name of the signature algorithm as a string
    pub fn signature_name(&self) -> &'static str {
        match self.signature {
            SignatureAlgorithm::Dilithium3 => "CRYSTALS-Dilithium-3",
            SignatureAlgorithm::Dilithium2 => "CRYSTALS-Dilithium-2",
            SignatureAlgorithm::Dilithium5 => "CRYSTALS-Dilithium-5",
        }
    }
    
    /// Get the name of the symmetric algorithm as a string
    pub fn symmetric_name(&self) -> &'static str {
        match self.symmetric {
            SymmetricAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            SymmetricAlgorithm::Aes256Gcm => "AES-256-GCM",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.key_exchange, KeyExchangeAlgorithm::Kyber768);
        assert_eq!(config.signature, SignatureAlgorithm::Dilithium3);
        assert_eq!(config.symmetric, SymmetricAlgorithm::ChaCha20Poly1305);
    }
    
    #[test]
    fn test_custom_config() {
        let config = CryptoConfig::with_algorithms(
            KeyExchangeAlgorithm::Kyber1024,
            SignatureAlgorithm::Dilithium5,
            SymmetricAlgorithm::Aes256Gcm,
        );
        assert_eq!(config.key_exchange, KeyExchangeAlgorithm::Kyber1024);
        assert_eq!(config.signature, SignatureAlgorithm::Dilithium5);
        assert_eq!(config.symmetric, SymmetricAlgorithm::Aes256Gcm);
    }
    
    #[test]
    fn test_preset_configs() {
        let lightweight = CryptoConfig::lightweight();
        assert_eq!(lightweight.key_exchange, KeyExchangeAlgorithm::Kyber512);
        assert_eq!(lightweight.signature, SignatureAlgorithm::Dilithium2);
        
        let high_security = CryptoConfig::high_security();
        assert_eq!(high_security.key_exchange, KeyExchangeAlgorithm::Kyber1024);
        assert_eq!(high_security.signature, SignatureAlgorithm::Dilithium5);
        
        let hw_optimized = CryptoConfig::hardware_optimized();
        assert_eq!(hw_optimized.symmetric, SymmetricAlgorithm::Aes256Gcm);
    }
    
    #[test]
    fn test_algorithm_names() {
        let config = CryptoConfig::default();
        assert_eq!(config.key_exchange_name(), "CRYSTALS-Kyber-768");
        assert_eq!(config.signature_name(), "CRYSTALS-Dilithium-3");
        assert_eq!(config.symmetric_name(), "ChaCha20-Poly1305");
    }
}