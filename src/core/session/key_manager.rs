/*!
Enhanced key management for the PQC protocol.

This module provides functionality for key exchange, key management,
and derived key handling for the session, supporting multiple algorithms
and secure memory.
*/

use crate::core::{
    error::{Result, Error},
    crypto::{
        key_exchange::KeyExchange,
        cipher::Cipher,
        config::{CryptoConfig, KeyExchangeAlgorithm, SymmetricAlgorithm},
        KyberPublicKey, 
        KyberCiphertext,
    },
    constants::sizes,
    memory::{SecureMemory, SecureMemoryManager},
};

use pqcrypto_traits::kem::SharedSecret;

// New imports for enhanced security
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;
use crate::core::memory::protection::ProtectedMemory;
use crate::core::memory::heapless_vec::{SecureHeaplessVec, SecureVec32};
use crate::core::security::constant_time;
use crate::core::security::hardware_security::{HardwareSecurityManager, HardwareSecurityCapability};
use subtle::ConstantTimeEq;

/// Key Manager handles cryptographic key management for the session
pub struct KeyManager {
    /// Kyber public key - use fixed-size stack allocation
    kyber_public_key: Option<SecureHeaplessVec<u8, 1184>>,
    
    /// Kyber secret key (protected by SecureMemory and ZeroizeOnDrop)
    kyber_secret_key: Option<ZeroizeOnDrop<ProtectedMemory<Vec<u8>>>>,
    
    /// Encryption key (protected with multiple layers of security)
    encryption_key: Option<ZeroizeOnDrop<ProtectedMemory<[u8; sizes::chacha::KEY_SIZE]>>>,
    
    /// Encryption cipher
    cipher: Option<Cipher>,
    
    /// Current algorithm for key exchange
    key_exchange_algorithm: KeyExchangeAlgorithm,
    
    /// Current algorithm for symmetric encryption
    symmetric_algorithm: SymmetricAlgorithm,
    
    /// Temporary storage for the key exchange secret key during rotation
    /// This is only used during key rotation
    temp_secret_key: Option<ZeroizeOnDrop<Vec<u8>>>,
    
    /// Hardware security module for secure key storage when available
    hw_security: Option<HardwareSecurityManager>,
    
    /// Key identifier in hardware security module
    hsm_key_id: Option<String>,
    
    /// Whether the encryption key is stored in HSM
    key_in_hsm: bool,
}

impl KeyManager {
    /// Create a new key manager with default algorithms
    pub fn new() -> Self {
        // Try to initialize hardware security
        let hw_security = if cfg!(feature = "hardware-security") {
            Some(HardwareSecurityManager::new())
        } else {
            None
        };
        
        // Generate a unique key ID
        let hsm_key_id = Some(format!("kyber-key-{}", uuid::Uuid::new_v4()));
        
        Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            encryption_key: None,
            cipher: None,
            key_exchange_algorithm: KeyExchangeAlgorithm::default(),
            symmetric_algorithm: SymmetricAlgorithm::default(),
            temp_secret_key: None,
            hw_security,
            hsm_key_id,
            key_in_hsm: false,
        }
    }
    
    /// Create a new key manager with specified algorithms
    pub fn new_with_config(config: &CryptoConfig) -> Result<Self> {
        // Try to initialize hardware security
        let hw_security = if cfg!(feature = "hardware-security") {
            Some(HardwareSecurityManager::new())
        } else {
            None
        };
        
        // Generate a unique key ID
        let hsm_key_id = Some(format!("kyber-key-{}", uuid::Uuid::new_v4()));
        
        Ok(Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            encryption_key: None,
            cipher: None,
            key_exchange_algorithm: config.key_exchange,
            symmetric_algorithm: config.symmetric,
            temp_secret_key: None,
            hw_security,
            hsm_key_id,
            key_in_hsm: false,
        })
    }
    
    /// Get the current key exchange algorithm
    pub fn key_exchange_algorithm(&self) -> KeyExchangeAlgorithm {
        self.key_exchange_algorithm
    }
    
    /// Get the current symmetric algorithm
    pub fn symmetric_algorithm(&self) -> SymmetricAlgorithm {
        self.symmetric_algorithm
    }
    
    /// Initialize key exchange (client side)
    pub fn init_key_exchange(&mut self) -> Result<KyberPublicKey> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Generate key pair
        let (public_key_bytes, secret_key_bytes) = key_exchanger.generate_keypair()?;
        
        // Store keys, using secure memory wrappers
        let mut public_key_stack = SecureHeaplessVec::<u8, 1184>::new();
        for &byte in &public_key_bytes {
            let _ = public_key_stack.push(byte);
        }
        
        self.kyber_public_key = Some(public_key_stack);
        
        // Multiple layers of protection for the secret key
        self.kyber_secret_key = Some(
            ZeroizeOnDrop::new(
                ProtectedMemory::new(secret_key_bytes)
            )
        );
        
        // Convert bytes to KyberPublicKey (this is for backward compatibility)
        let public_key = KyberPublicKey::from_bytes(&public_key_bytes)?;
        
        Ok(public_key)
    }
    
    /// Initialize key exchange with memory manager (client side)
    pub fn init_with_memory_manager(&mut self, memory_manager: &SecureMemoryManager) -> Result<KyberPublicKey> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Generate key pair
        let (public_key_bytes, secret_key_bytes) = key_exchanger.generate_keypair()?;
        
        // Store public key in stack-based vector
        let mut public_key_stack = SecureHeaplessVec::<u8, 1184>::new();
        for &byte in &public_key_bytes {
            let _ = public_key_stack.push(byte);
        }
        
        self.kyber_public_key = Some(public_key_stack);
        
        // If hardware security is available, try to use it
        if memory_manager.is_hardware_security_enabled() && 
           memory_manager.has_hw_capability(HardwareSecurityCapability::KeyStorage) {
            if let Some(hsm_key_id) = &self.hsm_key_id {
                // Store the secret key in HSM
                memory_manager.store_key_in_hsm(hsm_key_id, &secret_key_bytes)?;
                self.key_in_hsm = true;
            }
        }
        
        // Always store in protected memory as a backup
        self.kyber_secret_key = Some(
            ZeroizeOnDrop::new(
                memory_manager.protected_memory(secret_key_bytes)
            )
        );
        
        // Convert bytes to KyberPublicKey (for backward compatibility)
        let public_key = KyberPublicKey::from_bytes(&public_key_bytes)?;
        
        Ok(public_key)
    }
    
    /// Accept key exchange (server side)
    pub fn accept_key_exchange(&mut self, client_public_key: &KyberPublicKey) -> Result<KyberCiphertext> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Encapsulate shared secret
        let client_pk_bytes = client_public_key.as_bytes();
        let (shared_secret, ciphertext_bytes) = key_exchanger.encapsulate(client_pk_bytes)?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Store the encryption key in protected memory with ZeroizeOnDrop
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                ProtectedMemory::new(encryption_key)
            )
        );
        
        // Initialize the cipher
        self.cipher = Some(Cipher::new(&encryption_key, self.symmetric_algorithm)?);
        
        // Convert bytes to KyberCiphertext (for backward compatibility)
        let ciphertext = KyberCiphertext::from_bytes(&ciphertext_bytes)?;
        
        Ok(ciphertext)
    }
    
    /// Accept key exchange with memory manager (server side)
    pub fn accept_key_exchange_with_memory_manager(
        &mut self, 
        client_public_key: &KyberPublicKey,
        memory_manager: &SecureMemoryManager
    ) -> Result<KyberCiphertext> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Encapsulate shared secret
        let client_pk_bytes = client_public_key.as_bytes();
        let (shared_secret, ciphertext_bytes) = key_exchanger.encapsulate(client_pk_bytes)?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // If hardware security is available, try to use it
        if memory_manager.is_hardware_security_enabled() && 
           memory_manager.has_hw_capability(HardwareSecurityCapability::KeyStorage) {
            if let Some(hsm_key_id) = &self.hsm_key_id {
                // Store the encryption key in HSM
                memory_manager.store_key_in_hsm(hsm_key_id, &encryption_key)?;
                self.key_in_hsm = true;
            }
        }
        
        // Always store in protected memory as a backup
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                memory_manager.protected_key32(encryption_key)
            )
        );
        
        // Initialize the cipher
        self.cipher = Some(Cipher::new(&encryption_key, self.symmetric_algorithm)?);
        
        // Convert bytes to KyberCiphertext (for backward compatibility)
        let ciphertext = KyberCiphertext::from_bytes(&ciphertext_bytes)?;
        
        Ok(ciphertext)
    }
    
    /// Process key exchange response (client side)
    pub fn process_key_exchange(&mut self, ciphertext: &KyberCiphertext) -> Result<()> {
        // Get the secret key from SecureMemory
        let secure_kyber_secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Secret key not available".into()))?;
        
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Temporarily unprotect to access the key
        let inner_key = secure_kyber_secret_key.inner();
        
        // Decapsulate shared secret
        let shared_secret = key_exchanger.decapsulate(
            ciphertext.as_bytes(),
            inner_key
        )?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Store the encryption key in protected memory with ZeroizeOnDrop
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                ProtectedMemory::new(encryption_key)
            )
        );
        
        // Initialize the cipher
        self.cipher = Some(Cipher::new(&encryption_key, self.symmetric_algorithm)?);
        
        Ok(())
    }
    
    /// Process key exchange response with memory manager (client side)
    pub fn process_key_exchange_with_memory_manager(
        &mut self, 
        ciphertext: &KyberCiphertext,
        memory_manager: &SecureMemoryManager
    ) -> Result<()> {
        // Get the secret key from SecureMemory
        let secure_kyber_secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Secret key not available".into()))?;
        
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Temporarily unprotect to access the key
        let inner_key = secure_kyber_secret_key.inner();
        
        // Decapsulate shared secret
        let shared_secret = key_exchanger.decapsulate(
            ciphertext.as_bytes(),
            inner_key
        )?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // If hardware security is available, try to use it
        if memory_manager.is_hardware_security_enabled() && 
           memory_manager.has_hw_capability(HardwareSecurityCapability::KeyStorage) {
            if let Some(hsm_key_id) = &self.hsm_key_id {
                // Store the encryption key in HSM
                memory_manager.store_key_in_hsm(hsm_key_id, &encryption_key)?;
                self.key_in_hsm = true;
            }
        }
        
        // Always store in protected memory as a backup
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                memory_manager.protected_key32(encryption_key)
            )
        );
        
        // Initialize the cipher
        self.cipher = Some(Cipher::new(&encryption_key, self.symmetric_algorithm)?);
        
        Ok(())
    }
    
    /// Get the current Kyber public key (if available)
    pub fn get_public_key(&self) -> Option<&[u8]> {
        self.kyber_public_key.as_ref().map(|pk| pk.as_ref())
    }
    
    /// Access to the cipher for encryption/decryption operations
    pub fn get_cipher(&self) -> Result<&Cipher> {
        // Check if we need to retrieve key from HSM first
        if self.key_in_hsm && self.cipher.is_none() && self.encryption_key.is_none() {
            self.retrieve_key_from_hsm()?;
        }
        
        self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Access to the cipher for encryption/decryption operations (mutable)
    pub fn get_cipher_mut(&mut self) -> Result<&mut Cipher> {
        // Check if we need to retrieve key from HSM first
        if self.key_in_hsm && self.cipher.is_none() && self.encryption_key.is_none() {
            self.retrieve_key_from_hsm()?;
        }
        
        self.cipher.as_mut()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Get a reference to the encryption key
    pub fn get_encryption_key(&self) -> Result<&ZeroizeOnDrop<ProtectedMemory<[u8; sizes::chacha::KEY_SIZE]>>> {
        // Check if we need to retrieve key from HSM first
        if self.key_in_hsm && self.encryption_key.is_none() {
            self.retrieve_key_from_hsm()?;
        }
        
        self.encryption_key.as_ref()
            .ok_or_else(|| Error::Internal("Encryption key not initialized".into()))
    }
    
    /// Get a mutable reference to the encryption key
    pub fn get_encryption_key_mut(&mut self) -> Result<&mut ZeroizeOnDrop<ProtectedMemory<[u8; sizes::chacha::KEY_SIZE]>>> {
        // Check if we need to retrieve key from HSM first
        if self.key_in_hsm && self.encryption_key.is_none() {
            self.retrieve_key_from_hsm()?;
        }
        
        self.encryption_key.as_mut()
            .ok_or_else(|| Error::Internal("Encryption key not initialized".into()))
    }
    
    /// Store a key in hardware security module
    pub fn store_key_in_hsm(&mut self) -> Result<bool> {
        if let (Some(hw), Some(key_id), Some(ref enc_key)) = (&self.hw_security, &self.hsm_key_id, &self.encryption_key) {
            if hw.is_available() && hw.supports(HardwareSecurityCapability::KeyStorage) {
                // Access the inner key data (temporarily unprotect)
                let key_data = enc_key.inner();
                
                // Store the key in HSM
                match hw.store_key(key_id, key_data) {
                    Ok(_) => {
                        self.key_in_hsm = true;
                        Ok(true)
                    }
                    Err(_) => {
                        // Failed to store in HSM
                        self.key_in_hsm = false;
                        Ok(false)
                    }
                }
            } else {
                // HSM not available or doesn't support key storage
                self.key_in_hsm = false;
                Ok(false)
            }
        } else {
            // No HSM, key ID, or encryption key
            self.key_in_hsm = false;
            Ok(false)
        }
    }
    
    /// Retrieve a key from hardware security module
    pub fn retrieve_key_from_hsm(&mut self) -> Result<bool> {
        if !self.key_in_hsm {
            return Ok(false);
        }
        
        if let (Some(hw), Some(key_id)) = (&self.hw_security, &self.hsm_key_id) {
            // Retrieve the key from HSM
            match hw.retrieve_key(key_id)? {
                Some(key_data) => {
                    // Ensure the key is the correct size
                    if key_data.len() == sizes::chacha::KEY_SIZE {
                        // Convert to array
                        let mut key_array = [0u8; sizes::chacha::KEY_SIZE];
                        key_array.copy_from_slice(&key_data);
                        
                        // Store in protected memory
                        self.encryption_key = Some(
                            ZeroizeOnDrop::new(
                                ProtectedMemory::new(key_array)
                            )
                        );
                        
                        // Initialize cipher
                        self.cipher = Some(Cipher::new(&key_array, self.symmetric_algorithm)?);
                        
                        Ok(true)
                    } else {
                        // Incorrect key size
                        self.key_in_hsm = false;
                        Ok(false)
                    }
                }
                None => {
                    // Key not found in HSM
                    self.key_in_hsm = false;
                    Ok(false)
                }
            }
        } else {
            // No HSM or key ID
            self.key_in_hsm = false;
            Ok(false)
        }
    }
    
    /// Clear sensitive keys (useful during key rotation)
    pub fn clear_keys(&mut self) {
        // Clear Kyber keys - using ZeroizeOnDrop ensures proper cleanup
        self.kyber_public_key = None;
        self.kyber_secret_key = None;
        
        // Clear temporary secret key - using ZeroizeOnDrop ensures proper cleanup
        self.temp_secret_key = None;
        
        // Note: We don't clear encryption_key and cipher 
        // as they're needed until new ones are established
    }
    
    /// Update the encryption key and cipher
    pub fn update_encryption(&mut self, new_encryption_key: [u8; sizes::chacha::KEY_SIZE], algorithm: SymmetricAlgorithm) -> Result<()> {
        // Store in protected memory with ZeroizeOnDrop
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                ProtectedMemory::new(new_encryption_key)
            )
        );
        
        // Initialize cipher with the new key
        self.cipher = Some(Cipher::new(&new_encryption_key, algorithm)?);
        self.symmetric_algorithm = algorithm;
        
        Ok(())
    }
    
    /// Update the encryption key and cipher with memory manager
    pub fn update_encryption_with_memory_manager(
        &mut self,
        new_encryption_key: [u8; sizes::chacha::KEY_SIZE],
        algorithm: SymmetricAlgorithm,
        memory_manager: &SecureMemoryManager
    ) -> Result<()> {
        // If hardware security is available, try to use it
        if memory_manager.is_hardware_security_enabled() && 
           memory_manager.has_hw_capability(HardwareSecurityCapability::KeyStorage) {
            if let Some(hsm_key_id) = &self.hsm_key_id {
                // Store the encryption key in HSM
                memory_manager.store_key_in_hsm(hsm_key_id, &new_encryption_key)?;
                self.key_in_hsm = true;
            }
        }
        
        // Store in protected memory as a backup
        self.encryption_key = Some(
            ZeroizeOnDrop::new(
                memory_manager.protected_key32(new_encryption_key)
            )
        );
        
        // Initialize cipher with the new key
        self.cipher = Some(Cipher::new(&new_encryption_key, algorithm)?);
        self.symmetric_algorithm = algorithm;
        
        Ok(())
    }
    
    /// Store a temporary secret key for key rotation
    pub fn store_temporary_secret_key(&mut self, secret_key: Vec<u8>) {
        // Use ZeroizeOnDrop to ensure the temporary key is cleared when no longer needed
        self.temp_secret_key = Some(ZeroizeOnDrop::new(secret_key));
    }
    
    /// Get the temporary secret key (consumed)
    pub fn get_temporary_secret_key(&mut self) -> Option<Vec<u8>> {
        // Unwrap the ZeroizeOnDrop wrapper to get the inner value
        self.temp_secret_key.take().map(|key| key.into_inner())
    }
    
    /// Generate a new key pair for rotation
    pub fn generate_rotation_keypair(&mut self) -> Result<Vec<u8>> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Generate new key pair
        let (public_key_bytes, secret_key_bytes) = key_exchanger.generate_keypair()?;
        
        // Store the secret key temporarily - use ZeroizeOnDrop to ensure it's cleared
        self.store_temporary_secret_key(secret_key_bytes);
        
        // Return the public key
        Ok(public_key_bytes)
    }
    
    /// Generate a new key pair for rotation with memory manager
    pub fn generate_rotation_keypair_with_memory_manager(
        &mut self,
        memory_manager: &SecureMemoryManager
    ) -> Result<Vec<u8>> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Generate new key pair
        let (public_key_bytes, secret_key_bytes) = key_exchanger.generate_keypair()?;
        
        // For key rotation, we just store it temporarily, not in secure memory
        // because it's only needed briefly during the rotation process
        // Still use ZeroizeOnDrop to ensure it's cleared when no longer needed
        self.store_temporary_secret_key(secret_key_bytes);
        
        // Return the public key
        Ok(public_key_bytes)
    }
}

// Implement Zeroize trait to clear sensitive data
impl crate::core::memory::zeroize::Zeroize for KeyManager {
    fn zeroize(&mut self) {
        // KeyManager contains various sensitive components that should be zeroized
        
        // Clear the public key
        self.kyber_public_key = None;
        
        // Clear the secret key - ZeroizeOnDrop handles proper zeroization
        self.kyber_secret_key = None;
        
        // Clear the encryption key - ZeroizeOnDrop handles proper zeroization
        self.encryption_key = None;
        
        // Clear the cipher
        self.cipher = None;
        
        // Clear temporary secret key - ZeroizeOnDrop handles proper zeroization
        self.temp_secret_key = None;
        
        // We don't need to clear algorithm selections as they're not sensitive
    }
}

// Implement Drop to ensure sensitive data is cleared
impl Drop for KeyManager {
    fn drop(&mut self) {
        // Explicit zeroization
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::config::CryptoConfig;
    use crate::core::memory::MemorySecurity;
    
    #[test]
    fn test_key_exchange() -> Result<()> {
        let config = CryptoConfig::default();
        let mut client_key_manager = KeyManager::new_with_config(&config)?;
        let mut server_key_manager = KeyManager::new_with_config(&config)?;
        
        // Client initiates key exchange
        let client_public_key = client_key_manager.init_key_exchange()?;
        
        // Server accepts key exchange
        let ciphertext = server_key_manager.accept_key_exchange(&client_public_key)?;
        
        // Client processes server's response
        client_key_manager.process_key_exchange(&ciphertext)?;
        
        // Verify both sides have initialized the cipher
        let client_cipher = client_key_manager.get_cipher()?;
        let server_cipher = server_key_manager.get_cipher()?;
        
        assert!(client_cipher.is_initialized());
        assert!(server_cipher.is_initialized());
        
        Ok(())
    }
    
    #[test]
    fn test_key_exchange_with_memory_manager() -> Result<()> {
        let config = CryptoConfig::default();
        let mut client_key_manager = KeyManager::new_with_config(&config)?;
        let mut server_key_manager = KeyManager::new_with_config(&config)?;
        
        // Create memory managers
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Client initiates key exchange with memory manager
        let client_public_key = client_key_manager.init_with_memory_manager(&memory_manager)?;
        
        // Server accepts key exchange with memory manager
        let ciphertext = server_key_manager.accept_key_exchange_with_memory_manager(
            &client_public_key, &memory_manager)?;
        
        // Client processes server's response with memory manager
        client_key_manager.process_key_exchange_with_memory_manager(
            &ciphertext, &memory_manager)?;
        
        // Verify both sides have initialized the cipher
        let client_cipher = client_key_manager.get_cipher()?;
        let server_cipher = server_key_manager.get_cipher()?;
        
        assert!(client_cipher.is_initialized());
        assert!(server_cipher.is_initialized());
        
        Ok(())
    }
    
    #[test]
    fn test_key_zeroization() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        
        // Initialize key exchange
        let _public_key = key_manager.init_key_exchange()?;
        
        // Manually zeroize
        key_manager.zeroize();
        
        // After zeroization, the keys should be cleared
        assert!(key_manager.kyber_public_key.is_none());
        assert!(key_manager.kyber_secret_key.is_none());
        
        Ok(())
    }
    
    #[test]
    fn test_encryption_key_protection() -> Result<()> {
        let config = CryptoConfig::default();
        let mut client_key_manager = KeyManager::new_with_config(&config)?;
        let mut server_key_manager = KeyManager::new_with_config(&config)?;
        
        // Perform key exchange
        let client_public_key = client_key_manager.init_key_exchange()?;
        let ciphertext = server_key_manager.accept_key_exchange(&client_public_key)?;
        client_key_manager.process_key_exchange(&ciphertext)?;
        
        // Get the protected encryption key
        let enc_key = client_key_manager.get_encryption_key()?;
        
        // Should be able to use it for operations but not directly access it
        // due to the ProtectedMemory wrapper
        let is_protected = enc_key.inner().is_protected();
        println!("Key is protected: {}", is_protected);
        
        // The key should be available for use through deref
        assert_eq!(enc_key.len(), sizes::chacha::KEY_SIZE);
        
        Ok(())
    }
    
    #[test]
    fn test_hardware_security() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Maximum);
        
        // Enable hardware security in the memory manager
        memory_manager.enable_hardware_security();
        
        // Check if HSM is actually available
        if let Some(hw) = &key_manager.hw_security {
            if hw.is_available() {
                println!("Hardware security module available");
                
                // Initialize key exchange with HSM
                let client_public_key = key_manager.init_with_memory_manager(&memory_manager)?;
                
                // Check if key was stored in HSM
                println!("Key in HSM: {}", key_manager.key_in_hsm);
                
                // If key is in HSM, try to retrieve it
                if key_manager.key_in_hsm {
                    let retrieved = key_manager.retrieve_key_from_hsm()?;
                    println!("Key retrieved from HSM: {}", retrieved);
                }
            } else {
                println!("Hardware security module not available");
            }
        } else {
            println!("No hardware security module");
        }
        
        Ok(())
    }
    
    #[test]
    fn test_temporary_key_rotation() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        
        // Initialize key exchange
        let _public_key = key_manager.init_key_exchange()?;
        
        // Generate a temporary key for rotation
        let rotation_public_key = key_manager.generate_rotation_keypair()?;
        assert!(!rotation_public_key.is_empty());
        
        // Temporary secret key should be stored
        assert!(key_manager.temp_secret_key.is_some());
        
        // Extracting the secret key should consume it
        let temp_key = key_manager.get_temporary_secret_key();
        assert!(temp_key.is_some());
        
        // After getting the key, the temporary storage should be empty
        assert!(key_manager.temp_secret_key.is_none());
        
        Ok(())
    }
    
    #[test]
    fn test_constant_time_operations() -> Result<()> {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        memory_manager.enable_constant_time();
        
        // Test using constant-time comparison of keys
        let key1 = [0x42u8; 32];
        let key2 = [0x42u8; 32];
        let key3 = [0x43u8; 32];
        
        // Use subtle's constant-time comparison
        assert!(key1.ct_eq(&key2).into());
        assert!(!key1.ct_eq(&key3).into());
        
        Ok(())
    }
    
    #[test]
    fn test_update_encryption() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        
        // Initialize with a key exchange
        let _ = key_manager.init_key_exchange()?;
        
        // Create a new encryption key
        let new_key = [0x42u8; sizes::chacha::KEY_SIZE];
        
        // Update with the new key
        key_manager.update_encryption(new_key, SymmetricAlgorithm::ChaCha20Poly1305)?;
        
        // Verify the cipher is using the new algorithm
        assert_eq!(key_manager.symmetric_algorithm(), SymmetricAlgorithm::ChaCha20Poly1305);
        
        #[cfg(feature = "aes-gcm")]
        {
            // Update to a different algorithm if aes-gcm is available
            key_manager.update_encryption(new_key, SymmetricAlgorithm::Aes256Gcm)?;
            assert_eq!(key_manager.symmetric_algorithm(), SymmetricAlgorithm::Aes256Gcm);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_protected_memory_integration() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Maximum);
        
        // Enable read-only protection
        memory_manager.enable_read_only_protection();
        
        // Initialize key exchange with the memory manager
        let client_public_key = key_manager.init_with_memory_manager(&memory_manager)?;
        
        // Simulate server accepting the key exchange
        let mut server_key_manager = KeyManager::new_with_config(&config)?;
        let ciphertext = server_key_manager.accept_key_exchange(&client_public_key)?;
        
        // Process the server's response
        key_manager.process_key_exchange_with_memory_manager(&ciphertext, &memory_manager)?;
        
        // At this point, encryption key should be protected
        if let Some(ref enc_key) = key_manager.encryption_key {
            let is_protected = enc_key.inner().is_protected();
            println!("Encryption key is protected: {}", is_protected);
            
            // We should still be able to use the cipher
            let cipher = key_manager.get_cipher()?;
            assert!(cipher.is_initialized());
        }
        
        Ok(())
    }
}