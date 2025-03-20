/*!
Registry manager for cryptographic algorithms.

This module provides a central registry for supported algorithms
to enable runtime selection and configuration.
*/

use std::collections::HashMap;
use std::sync::RwLock;
use once_cell::sync::Lazy;

use crate::core::crypto::types::algorithms::{
    KeyExchangeAlgorithm, 
    SignatureAlgorithm, 
    SymmetricAlgorithm
};

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