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

/// Key Manager handles cryptographic key management for the session
pub struct KeyManager {
    /// Kyber public key
    kyber_public_key: Option<Vec<u8>>,
    
    /// Kyber secret key (protected by SecureMemory)
    kyber_secret_key: Option<SecureMemory<Vec<u8>>>,
    
    /// Encryption key (protected by SecureMemory)
    encryption_key: Option<SecureMemory<[u8; sizes::chacha::KEY_SIZE]>>,
    
    /// Encryption cipher
    cipher: Option<Cipher>,
    
    /// Current algorithm for key exchange
    key_exchange_algorithm: KeyExchangeAlgorithm,
    
    /// Current algorithm for symmetric encryption
    symmetric_algorithm: SymmetricAlgorithm,
    
    /// Temporary storage for the key exchange secret key during rotation
    /// This is only used during key rotation
    temp_secret_key: Option<Vec<u8>>,
}

impl KeyManager {
    /// Create a new key manager with default algorithms
    pub fn new() -> Self {
        Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            encryption_key: None,
            cipher: None,
            key_exchange_algorithm: KeyExchangeAlgorithm::default(),
            symmetric_algorithm: SymmetricAlgorithm::default(),
            temp_secret_key: None,
        }
    }
    
    /// Create a new key manager with specified algorithms
    pub fn new_with_config(config: &CryptoConfig) -> Result<Self> {
        Ok(Self {
            kyber_public_key: None,
            kyber_secret_key: None,
            encryption_key: None,
            cipher: None,
            key_exchange_algorithm: config.key_exchange,
            symmetric_algorithm: config.symmetric,
            temp_secret_key: None,
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
        
        // Store keys, wrapping the secret key in SecureMemory
        self.kyber_public_key = Some(public_key_bytes.clone());
        self.kyber_secret_key = Some(SecureMemory::new(secret_key_bytes));
        
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
        
        // Store keys, wrapping the secret key using the memory manager
        self.kyber_public_key = Some(public_key_bytes.clone());
        
        // Use the memory manager to create secure memory
        self.kyber_secret_key = Some(memory_manager.secure_memory(secret_key_bytes));
        
        // Convert bytes to KyberPublicKey (this is for backward compatibility)
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
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
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
        
        // Wrap the encryption key with SecureMemory using memory manager
        self.encryption_key = Some(memory_manager.secure_memory(encryption_key));
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
        
        // Decapsulate shared secret
        let shared_secret = key_exchanger.decapsulate(
            ciphertext.as_bytes(),
            secure_kyber_secret_key.as_ref()
        )?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
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
        
        // Decapsulate shared secret
        let shared_secret = key_exchanger.decapsulate(
            ciphertext.as_bytes(),
            secure_kyber_secret_key.as_ref()
        )?;
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(memory_manager.secure_memory(encryption_key));
        self.cipher = Some(Cipher::new(&encryption_key, self.symmetric_algorithm)?);
        
        Ok(())
    }
    
    /// Get the current Kyber public key (if available)
    pub fn get_public_key(&self) -> Option<&[u8]> {
        self.kyber_public_key.as_deref()
    }
    
    /// Get access to the cipher for encryption/decryption operations
    pub fn get_cipher(&self) -> Result<&Cipher> {
        self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Get access to the cipher for encryption/decryption operations (mutable)
    pub fn get_cipher_mut(&mut self) -> Result<&mut Cipher> {
        self.cipher.as_mut()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))
    }
    
    /// Get a reference to the encryption key
    pub fn get_encryption_key(&self) -> Result<&SecureMemory<[u8; sizes::chacha::KEY_SIZE]>> {
        self.encryption_key.as_ref()
            .ok_or_else(|| Error::Internal("Encryption key not initialized".into()))
    }
    
    /// Get a mutable reference to the encryption key
    pub fn get_encryption_key_mut(&mut self) -> Result<&mut SecureMemory<[u8; sizes::chacha::KEY_SIZE]>> {
        self.encryption_key.as_mut()
            .ok_or_else(|| Error::Internal("Encryption key not initialized".into()))
    }
    
    /// Clear sensitive keys (useful during key rotation)
    pub fn clear_keys(&mut self) {
        // Clear Kyber keys
        if let Some(ref mut key) = self.kyber_secret_key {
            key.clear();
        }
        self.kyber_public_key = None;
        self.kyber_secret_key = None;
        
        // Clear temporary secret key
        if let Some(ref mut key) = self.temp_secret_key {
            // Zero out the key data
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }
        self.temp_secret_key = None;
        
        // Note: We don't clear encryption_key and cipher 
        // as they're needed until new ones are established
    }
    
    /// Update the encryption key and cipher
    pub fn update_encryption(&mut self, new_encryption_key: [u8; sizes::chacha::KEY_SIZE], algorithm: SymmetricAlgorithm) -> Result<()> {
        self.encryption_key = Some(SecureMemory::new(new_encryption_key));
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
        self.encryption_key = Some(memory_manager.secure_memory(new_encryption_key));
        self.cipher = Some(Cipher::new(&new_encryption_key, algorithm)?);
        self.symmetric_algorithm = algorithm;
        Ok(())
    }
    
    /// Store a temporary secret key for key rotation
    pub fn store_temporary_secret_key(&mut self, secret_key: Vec<u8>) {
        self.temp_secret_key = Some(secret_key);
    }
    
    /// Get the temporary secret key (consumed)
    pub fn get_temporary_secret_key(&mut self) -> Option<Vec<u8>> {
        self.temp_secret_key.take()
    }
    
    /// Generate a new key pair for rotation
    pub fn generate_rotation_keypair(&mut self) -> Result<Vec<u8>> {
        // Create key exchanger with the configured algorithm
        let key_exchanger = KeyExchange::new(self.key_exchange_algorithm)?;
        
        // Generate new key pair
        let (public_key_bytes, secret_key_bytes) = key_exchanger.generate_keypair()?;
        
        // Store the secret key temporarily
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
        self.store_temporary_secret_key(secret_key_bytes);
        
        // Return the public key
        Ok(public_key_bytes)
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
    fn test_different_algorithms() -> Result<()> {
        // Test with high security configuration
        let high_sec_config = CryptoConfig::high_security();
        
        let mut client_key_manager = KeyManager::new_with_config(&high_sec_config)?;
        let mut server_key_manager = KeyManager::new_with_config(&high_sec_config)?;
        
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
        
        // Check that both are using the expected algorithms
        assert_eq!(client_key_manager.key_exchange_algorithm(), high_sec_config.key_exchange);
        assert_eq!(server_key_manager.symmetric_algorithm(), high_sec_config.symmetric);
        
        Ok(())
    }
    
    #[test]
    fn test_key_rotation() -> Result<()> {
        let config = CryptoConfig::default();
        let mut key_manager = KeyManager::new_with_config(&config)?;
        
        // Generate initial key pair
        let _ = key_manager.init_key_exchange()?;
        
        // Generate rotation key pair
        let rotation_public_key = key_manager.generate_rotation_keypair()?;
        
        // Temporary secret key should be stored
        assert!(key_manager.get_temporary_secret_key().is_some());
        
        // After getting the secret key, it should be consumed
        assert!(key_manager.get_temporary_secret_key().is_none());
        
        // Rotation public key should not be None
        assert!(!rotation_public_key.is_empty());
        
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
}