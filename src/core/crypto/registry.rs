/*!
Registry for cryptographic algorithms used in the PQC protocol.

This module provides a central registry for supported algorithms
to enable runtime selection and configuration.
*/

use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

use crate::core::crypto::config::{KeyExchangeAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};

/// Registry of supported cryptographic algorithms
pub struct CryptoRegistry {
    /// Available key exchange algorithms
    key_exchange_algorithms: HashMap<String, KeyExchangeAlgorithm>,
    
    /// Available signature algorithms
    signature_algorithms: HashMap<String, SignatureAlgorithm>,
    
    /// Available symmetric encryption algorithms
    symmetric_algorithms: HashMap<String, SymmetricAlgorithm>,
}

impl CryptoRegistry {
    /// Create a new registry with default algorithms
    fn new() -> Self {
        let mut registry = Self {
            key_exchange_algorithms: HashMap::new(),
            signature_algorithms: HashMap::new(),
            symmetric_algorithms: HashMap::new(),
        };
        
        // Register default algorithms
        registry.register_key_exchange("kyber768", KeyExchangeAlgorithm::Kyber768);
        registry.register_signature("dilithium3", SignatureAlgorithm::Dilithium3);
        registry.register_symmetric("chacha20poly1305", SymmetricAlgorithm::ChaCha20Poly1305);
        
        // Register optional algorithms based on features
        #[cfg(feature = "kyber512")]
        registry.register_key_exchange("kyber512", KeyExchangeAlgorithm::Kyber512);
        
        #[cfg(feature = "kyber1024")]
        registry.register_key_exchange("kyber1024", KeyExchangeAlgorithm::Kyber1024);
        
        #[cfg(feature = "dilithium2")]
        registry.register_signature("dilithium2", SignatureAlgorithm::Dilithium2);
        
        #[cfg(feature = "dilithium5")]
        registry.register_signature("dilithium5", SignatureAlgorithm::Dilithium5);
        
        #[cfg(feature = "aes-gcm")]
        registry.register_symmetric("aes256gcm", SymmetricAlgorithm::Aes256Gcm);
        
        registry
    }
    
    // Register methods for each type
    fn register_key_exchange(&mut self, name: &str, algorithm: KeyExchangeAlgorithm) {
        self.key_exchange_algorithms.insert(name.to_string(), algorithm);
    }
    
    fn register_signature(&mut self, name: &str, algorithm: SignatureAlgorithm) {
        self.signature_algorithms.insert(name.to_string(), algorithm);
    }
    
    fn register_symmetric(&mut self, name: &str, algorithm: SymmetricAlgorithm) {
        self.symmetric_algorithms.insert(name.to_string(), algorithm);
    }
    
    // Lookup methods for each type
    pub fn get_key_exchange(&self, name: &str) -> Option<KeyExchangeAlgorithm> {
        self.key_exchange_algorithms.get(name).copied()
    }
    
    pub fn get_signature(&self, name: &str) -> Option<SignatureAlgorithm> {
        self.signature_algorithms.get(name).copied()
    }
    
    pub fn get_symmetric(&self, name: &str) -> Option<SymmetricAlgorithm> {
        self.symmetric_algorithms.get(name).copied()
    }
    
    // List available algorithms
    pub fn list_key_exchange_algorithms(&self) -> Vec<String> {
        self.key_exchange_algorithms.keys().cloned().collect()
    }
    
    pub fn list_signature_algorithms(&self) -> Vec<String> {
        self.signature_algorithms.keys().cloned().collect()
    }
    
    pub fn list_symmetric_algorithms(&self) -> Vec<String> {
        self.symmetric_algorithms.keys().cloned().collect()
    }
}

// Global registry instance
static REGISTRY: Lazy<RwLock<CryptoRegistry>> = Lazy::new(|| {
    RwLock::new(CryptoRegistry::new())
});

// Public API

/// Get a read-only reference to the global registry
pub fn get_registry() -> std::sync::RwLockReadGuard<'static, CryptoRegistry> {
    REGISTRY.read().unwrap()
}

/// Register a new key exchange algorithm
pub fn register_key_exchange(name: &str, algorithm: KeyExchangeAlgorithm) {
    let mut registry = REGISTRY.write().unwrap();
    registry.register_key_exchange(name, algorithm);
}

/// Register a new signature algorithm
pub fn register_signature(name: &str, algorithm: SignatureAlgorithm) {
    let mut registry = REGISTRY.write().unwrap();
    registry.register_signature(name, algorithm);
}

/// Register a new symmetric algorithm
pub fn register_symmetric(name: &str, algorithm: SymmetricAlgorithm) {
    let mut registry = REGISTRY.write().unwrap();
    registry.register_symmetric(name, algorithm);
}

/// Get a key exchange algorithm by name
pub fn get_key_exchange(name: &str) -> Option<KeyExchangeAlgorithm> {
    let registry = get_registry();
    registry.get_key_exchange(name)
}

/// Get a signature algorithm by name
pub fn get_signature(name: &str) -> Option<SignatureAlgorithm> {
    let registry = get_registry();
    registry.get_signature(name)
}

/// Get a symmetric algorithm by name
pub fn get_symmetric(name: &str) -> Option<SymmetricAlgorithm> {
    let registry = get_registry();
    registry.get_symmetric(name)
}

/// List all registered key exchange algorithms
pub fn list_key_exchange_algorithms() -> Vec<String> {
    let registry = get_registry();
    registry.list_key_exchange_algorithms()
}

/// List all registered signature algorithms
pub fn list_signature_algorithms() -> Vec<String> {
    let registry = get_registry();
    registry.list_signature_algorithms()
}

/// List all registered symmetric algorithms
pub fn list_symmetric_algorithms() -> Vec<String> {
    let registry = get_registry();
    registry.list_symmetric_algorithms()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_defaults() {
        let registry = get_registry();
        
        // Check default algorithms are registered
        assert!(registry.get_key_exchange("kyber768").is_some());
        assert!(registry.get_signature("dilithium3").is_some());
        assert!(registry.get_symmetric("chacha20poly1305").is_some());
        
        // Check the returned algorithms are correct
        assert_eq!(registry.get_key_exchange("kyber768"), Some(KeyExchangeAlgorithm::Kyber768));
        assert_eq!(registry.get_signature("dilithium3"), Some(SignatureAlgorithm::Dilithium3));
        assert_eq!(registry.get_symmetric("chacha20poly1305"), Some(SymmetricAlgorithm::ChaCha20Poly1305));
    }
    
    #[test]
    fn test_register_new_algorithm() {
        // Register a new algorithm
        register_key_exchange("test-algorithm", KeyExchangeAlgorithm::Kyber768);
        
        // Check it was registered correctly
        let registry = get_registry();
        assert!(registry.get_key_exchange("test-algorithm").is_some());
        assert_eq!(registry.get_key_exchange("test-algorithm"), Some(KeyExchangeAlgorithm::Kyber768));
    }
    
    #[test]
    fn test_list_algorithms() {
        let registry = get_registry();
        
        // Check we can list algorithms
        let key_exchanges = registry.list_key_exchange_algorithms();
        let signatures = registry.list_signature_algorithms();
        let symmetrics = registry.list_symmetric_algorithms();
        
        assert!(key_exchanges.contains(&"kyber768".to_string()));
        assert!(signatures.contains(&"dilithium3".to_string()));
        assert!(symmetrics.contains(&"chacha20poly1305".to_string()));
    }
}