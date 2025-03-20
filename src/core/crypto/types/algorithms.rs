/*!
Algorithm type definitions.

This module defines the various algorithm types and enums used
throughout the crypto subsystem.
*/

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

impl KeyExchangeAlgorithm {
    /// Get the name of the algorithm as a string
    pub fn name(&self) -> &'static str {
        match self {
            KeyExchangeAlgorithm::Kyber768 => "CRYSTALS-Kyber-768",
            KeyExchangeAlgorithm::Kyber512 => "CRYSTALS-Kyber-512",
            KeyExchangeAlgorithm::Kyber1024 => "CRYSTALS-Kyber-1024",
        }
    }
    
    /// Check if the algorithm is available in the current build
    pub fn is_available(&self) -> bool {
        match self {
            KeyExchangeAlgorithm::Kyber768 => true, // Always available
            KeyExchangeAlgorithm::Kyber512 => cfg!(feature = "kyber512"),
            KeyExchangeAlgorithm::Kyber1024 => cfg!(feature = "kyber1024"),
        }
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

impl SignatureAlgorithm {
    /// Get the name of the algorithm as a string
    pub fn name(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Dilithium3 => "CRYSTALS-Dilithium-3",
            SignatureAlgorithm::Dilithium2 => "CRYSTALS-Dilithium-2",
            SignatureAlgorithm::Dilithium5 => "CRYSTALS-Dilithium-5",
        }
    }
    
    /// Check if the algorithm is available in the current build
    pub fn is_available(&self) -> bool {
        match self {
            SignatureAlgorithm::Dilithium3 => true, // Always available
            SignatureAlgorithm::Dilithium2 => cfg!(feature = "dilithium2"),
            SignatureAlgorithm::Dilithium5 => cfg!(feature = "dilithium5"),
        }
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

impl SymmetricAlgorithm {
    /// Get the name of the algorithm as a string
    pub fn name(&self) -> &'static str {
        match self {
            SymmetricAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            SymmetricAlgorithm::Aes256Gcm => "AES-256-GCM",
        }
    }
    
    /// Check if the algorithm is available in the current build
    pub fn is_available(&self) -> bool {
        match self {
            SymmetricAlgorithm::ChaCha20Poly1305 => true, // Always available
            SymmetricAlgorithm::Aes256Gcm => cfg!(feature = "aes-gcm"),
        }
    }
}