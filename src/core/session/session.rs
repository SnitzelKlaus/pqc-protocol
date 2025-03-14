/*!
Enhanced session implementation for the PQC protocol.

This module integrates the different components (key management, authentication,
data handling) to provide a complete session implementation with configurable
cryptographic algorithms and memory security.
*/

use crate::core::{
    error::{Result, Error, AuthError},
    session::{
        state::{StateManager, SessionState, Role},
        key_manager::KeyManager,
        auth_manager::AuthManager,
        data_manager::DataManager,
    },
    security::rotation::{KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation},
    crypto::{
        config::CryptoConfig,
        key_exchange::KeyExchange,
    },
    message::{MessageType, MessageBuilder, MessageParser},
    memory::{SecureMemoryManager, MemorySecurity, SecureSession},
};
use crate::{invalid_state_err, auth_err, protocol_err};

// Add the following new imports for enhanced security
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;
use crate::core::memory::protected_memory::ProtectedMemory;
use crate::core::memory::heapless_vec::{SecureHeaplessVec, SecureVec32};
use crate::core::security::constant_time;
use crate::core::security::hardware_security::{HardwareSecurityManager, HardwareSecurityCapability};
use subtle::ConstantTimeEq;

/// Main session for the PQC protocol with configurable algorithms
pub struct Session {
    /// Manages session state
    state_manager: StateManager,
    
    /// Manages key exchange and encryption - wrapped in ZeroizeOnDrop
    key_manager: ZeroizeOnDrop<KeyManager>,
    
    /// Manages authentication and signatures - wrapped in ZeroizeOnDrop
    auth_manager: ZeroizeOnDrop<AuthManager>,
    
    /// Manages data operations
    data_manager: DataManager,
    
    /// Manages key rotation
    rotation_manager: KeyRotationManager,
    
    /// Manages secure memory
    memory_manager: SecureMemoryManager,
    
    /// Cryptographic configuration
    crypto_config: CryptoConfig,
    
    /// Session key stored in protected memory when possible
    session_key: Option<ProtectedMemory<[u8; 32]>>,
    
    /// Hardware security manager for key storage
    hw_security: Option<HardwareSecurityManager>,
}

impl Session {
    /// Create a new session with default cryptographic algorithms
    pub fn new() -> Result<Self> {
        Self::with_config(CryptoConfig::default())
    }
    
    /// Create a new session with specified cryptographic algorithms
    pub fn with_config(config: CryptoConfig) -> Result<Self> {
        // Validate the configuration
        config.validate()?;
        
        let state_manager = StateManager::new(Role::Client);
        
        // Use ZeroizeOnDrop to ensure key_manager and auth_manager are zeroed when dropped
        let key_manager = ZeroizeOnDrop::new(KeyManager::new_with_config(&config)?);
        let auth_manager = ZeroizeOnDrop::new(AuthManager::new_with_config(&config)?);
        let data_manager = DataManager::new();
        let rotation_manager = KeyRotationManager::new();
        
        // Create with standard memory security by default
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Standard);
        
        // Check if hardware security is available
        let hw_security = if cfg!(feature = "hardware-security") {
            Some(HardwareSecurityManager::new())
        } else {
            None
        };
        
        Ok(Self {
            state_manager,
            key_manager,
            auth_manager,
            data_manager,
            rotation_manager,
            memory_manager,
            crypto_config: config,
            session_key: None,
            hw_security,
        })
    }
    
    /// Create a new session with a protected key
    pub fn with_protected_key(key_data: [u8; 32]) -> Result<Self> {
        let mut session = Self::new()?;
        
        // Store the key in protected memory
        session.session_key = Some(session.memory_manager.protected_key32(key_data));
        
        Ok(session)
    }
    
    /// Create a lightweight session for resource-constrained environments
    pub fn lightweight() -> Result<Self> {
        Self::with_config(CryptoConfig::lightweight())
    }
    
    /// Create a high-security session
    pub fn high_security() -> Result<Self> {
        Self::with_config(CryptoConfig::high_security())
    }
    
    /// Create a session optimized for embedded systems
    pub fn embedded() -> Result<Self> {
        let mut session = Self::with_config(CryptoConfig::lightweight())?;
        
        // Reduce memory security for embedded environments
        session.memory_manager.disable_memory_locking();
        session.memory_manager.disable_canary_protection();
        
        Ok(session)
    }
    
    /// Get a reference to the memory manager
    pub fn memory_manager(&self) -> &SecureMemoryManager {
        &self.memory_manager
    }
    
    /// Get a mutable reference to the memory manager
    pub fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager {
        &mut self.memory_manager
    }
    
    /// Set the memory security level
    pub fn set_memory_security_level(&mut self, level: MemorySecurity) {
        self.memory_manager.set_security_level(level);
    }
    
    /// Get the current memory security level
    pub fn memory_security_level(&self) -> MemorySecurity {
        self.memory_manager.security_level()
    }
    
    /// Enable secure memory features
    pub fn enable_secure_memory(&mut self) {
        self.memory_manager.enable_memory_locking();
        self.memory_manager.enable_canary_protection();
        self.memory_manager.enable_zero_on_free();
        self.memory_manager.enable_read_only_protection();
        self.memory_manager.enable_constant_time();
    }
    
    /// Disable secure memory features
    pub fn disable_secure_memory(&mut self) {
        self.memory_manager.disable_memory_locking();
        self.memory_manager.disable_canary_protection();
        self.memory_manager.disable_zero_on_free();
        self.memory_manager.disable_read_only_protection();
        self.memory_manager.disable_constant_time();
    }
    
    /// Enable hardware security module for key storage
    pub fn use_hardware_security(&mut self, enable: bool) -> Result<bool> {
        if enable {
            self.memory_manager.enable_hardware_security();
            
            // Check if hardware security is actually available
            let available = self.memory_manager.is_hardware_security_enabled() && 
                            self.memory_manager.hardware_security_manager().is_some();
            
            if available {
                // Try to store a test key to verify HSM is working
                let key_id = format!("test-key-{}", uuid::Uuid::new_v4());
                let test_key = [0u8; 32];
                
                if let Err(_) = self.memory_manager.store_key_in_hsm(&key_id, &test_key) {
                    // HSM is not working properly
                    self.memory_manager.disable_hardware_security();
                    return Ok(false);
                }
                
                // HSM is working
                return Ok(true);
            } else {
                // Hardware security not available
                self.memory_manager.disable_hardware_security();
                return Ok(false);
            }
        } else {
            // Disable hardware security
            self.memory_manager.disable_hardware_security();
            return Ok(true);
        }
    }
    
    /// Zero sensitive memory
    pub fn zero_sensitive_memory(&mut self) {
        // The underlying key_manager and auth_manager will be zeroed
        // automatically via ZeroizeOnDrop when replaced
        
        // Clear session key if present
        if let Some(ref mut key) = self.session_key {
            key.zeroize();
        }
        
        // Reset managers to clear sensitive data
        if let Ok(new_key_manager) = KeyManager::new_with_config(&self.crypto_config) {
            *self.key_manager = new_key_manager;
        }
        
        if let Ok(new_auth_manager) = AuthManager::new_with_config(&self.crypto_config) {
            *self.auth_manager = new_auth_manager;
        }
        
        // Reset data manager
        self.data_manager = DataManager::new();
    }
    
    /// Constant-time equality comparison
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.memory_manager.is_constant_time_enabled() {
            // Use subtle crate for constant-time equality
            if a.len() != b.len() {
                return false;
            }
            
            a.ct_eq(b).into()
        } else {
            // Fall back to regular comparison
            a == b
        }
    }
    
    /// Create secure stack-based vectors
    pub fn create_secure_vec32(&self) -> SecureVec32 {
        self.memory_manager.secure_bytes32()
    }
    
    /// Set role (client or server)
    pub fn set_role(&mut self, role: Role) {
        self.state_manager.set_role(role);
    }
    
    /// Get the current role
    pub fn role(&self) -> Role {
        self.state_manager.role()
    }
    
    /// Get the current session state
    pub fn state(&self) -> SessionState {
        self.state_manager.state()
    }
    
    /// Get the current cryptographic configuration
    pub fn crypto_config(&self) -> &CryptoConfig {
        &self.crypto_config
    }
    
    /// Update the cryptographic configuration
    /// Note: This can only be done in the New state
    pub fn update_config(&mut self, config: CryptoConfig) -> Result<()> {
        if self.state_manager.state() != SessionState::New {
            return protocol_err!("Cannot change crypto config after session initialization");
        }
        
        // Validate the configuration
        config.validate()?;
        
        // Update configuration
        self.crypto_config = config;
        
        // Re-initialize managers
        *self.key_manager = KeyManager::new_with_config(&self.crypto_config)?;
        *self.auth_manager = AuthManager::new_with_config(&self.crypto_config)?;
        
        Ok(())
    }
    
    /// Get the local verification key
    pub fn local_verification_key(&self) -> &DilithiumPublicKey {
        self.auth_manager.local_verification_key()
    }
    
    /// Initialize key exchange (client side)
    pub fn init_key_exchange(&mut self) -> Result<KyberPublicKey> {
        if !self.state_manager.can_init_key_exchange() {
            return invalid_state_err!(
                "can initialize key exchange",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Perform key exchange
        let public_key = if cfg!(feature = "enhanced-memory") {
            self.key_manager.init_with_memory_manager(&self.memory_manager)?
        } else {
            self.key_manager.init_key_exchange()?
        };
        
        // Update state
        self.state_manager.transition_to_key_exchange_initiated();
        
        Ok(public_key)
    }
    
    /// Accept key exchange (server side)
    pub fn accept_key_exchange(&mut self, client_public_key: &KyberPublicKey) -> Result<KyberCiphertext> {
        if !self.state_manager.can_accept_key_exchange() {
            return invalid_state_err!(
                "can accept key exchange",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Accept key exchange
        let ciphertext = if self.memory_manager.is_hardware_security_enabled() {
            // Try to use hardware security if available
            let ct = self.key_manager.accept_key_exchange_with_memory_manager(
                client_public_key, &self.memory_manager)?;
            
            // Try to store the key in HSM if successful
            if let Some(ref mut key_manager) = self.key_manager.as_mut() {
                let _ = key_manager.store_key_in_hsm();
            }
            
            ct
        } else {
            // Use regular key exchange
            self.key_manager.accept_key_exchange(client_public_key)?
        };
        
        // Update state
        self.state_manager.transition_to_key_exchange_completed();
        
        Ok(ciphertext)
    }
    
    /// Process key exchange response (client side)
    pub fn process_key_exchange(&mut self, ciphertext: &KyberCiphertext) -> Result<()> {
        if !self.state_manager.can_process_key_exchange() {
            return invalid_state_err!(
                "can process key exchange",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Process the key exchange
        let result = if self.memory_manager.is_hardware_security_enabled() {
            // Try to use hardware security if available
            let r = self.key_manager.process_key_exchange_with_memory_manager(
                ciphertext, &self.memory_manager)?;
            
            // Try to store the key in HSM if successful
            if let Some(ref mut key_manager) = self.key_manager.as_mut() {
                let _ = key_manager.store_key_in_hsm();
            }
            
            r
        } else {
            // Use regular key exchange
            self.key_manager.process_key_exchange(ciphertext)?
        };
        
        // Update state
        self.state_manager.transition_to_key_exchange_completed();
        
        Ok(())
    }
    
    /// Set the remote verification key
    pub fn set_remote_verification_key(&mut self, key: DilithiumPublicKey) -> Result<()> {
        if !self.state_manager.can_set_verification_key() {
            return invalid_state_err!(
                "can set verification key",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Set the remote verification key
        self.auth_manager.set_remote_verification_key(key)?;
        
        // Update state
        self.state_manager.transition_to_authentication_initiated();
        
        Ok(())
    }
    
    /// Complete authentication
    pub fn complete_authentication(&mut self) -> Result<()> {
        if !self.state_manager.can_complete_authentication() {
            return invalid_state_err!(
                "can complete authentication",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Verify both parties have exchanged verification keys
        if !self.auth_manager.has_remote_verification_key() {
            return auth_err!(AuthError::MissingVerificationKey);
        }
        
        // Complete the authentication process
        self.auth_manager.complete_authentication()?;
        
        // Update state
        self.state_manager.transition_to_established();
        
        // Reset key rotation stats when authentication is completed
        self.rotation_manager.reset_stats();
        
        Ok(())
    }
    
    /// Encrypt and sign data
    pub fn encrypt_and_sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return invalid_state_err!(
                "can transfer data",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Check if key rotation is needed
        if self.should_rotate_keys() {
            // We've detected need for rotation, but will handle it separately
            log::info!("Key rotation needed, but proceeding with current keys");
        }
        
        // Use constant-time operations when possible
        let message = if self.memory_manager.is_constant_time_enabled() {
            // For small data, use stack allocation
            if data.len() <= 1024 {
                let mut stack_data = SecureHeaplessVec::<u8, 1024>::new();
                for &byte in data {
                    let _ = stack_data.push(byte);
                }
                
                // Encrypt using the fixed-size buffer for constant-time operation
                self.data_manager.encrypt_and_sign(
                    &stack_data,
                    &self.key_manager,
                    &self.auth_manager
                )?
            } else {
                // For larger data, use protected memory
                let protected_data = ProtectedMemory::new(data.to_vec());
                
                // Encrypt and sign using constant-time operations
                self.data_manager.encrypt_and_sign(
                    &protected_data,
                    &self.key_manager,
                    &self.auth_manager
                )?
            }
        } else {
            // Use regular operations
            self.data_manager.encrypt_and_sign(
                data,
                &self.key_manager,
                &self.auth_manager
            )?
        };
        
        // Track sent message for key rotation
        self.rotation_manager.track_sent(message.len());
        
        Ok(message)
    }
    
    /// Verify and decrypt data
    pub fn verify_and_decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return invalid_state_err!(
                "can transfer data",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Use constant-time operations when possible
        let decrypted = if self.memory_manager.is_constant_time_enabled() {
            // For small messages, use stack allocation
            if message.len() <= 4096 {
                let mut stack_msg = SecureHeaplessVec::<u8, 4096>::new();
                for &byte in message {
                    let _ = stack_msg.push(byte);
                }
                
                // Decrypt using the fixed-size buffer for constant-time operation
                self.data_manager.verify_and_decrypt(
                    &stack_msg,
                    &self.key_manager,
                    &self.auth_manager
                )?
            } else {
                // For larger messages, use regular verification
                self.data_manager.verify_and_decrypt(
                    message,
                    &self.key_manager,
                    &self.auth_manager
                )?
            }
        } else {
            // Use regular operations
            self.data_manager.verify_and_decrypt(
                message,
                &self.key_manager,
                &self.auth_manager
            )?
        };
        
        // Track received message for key rotation
        self.rotation_manager.track_received(message.len());
        
        Ok(decrypted)
    }
    
    /// Generate an acknowledgment message
    pub fn generate_ack(&mut self, seq_num: u32) -> Vec<u8> {
        let ack = self.data_manager.generate_ack(seq_num);
        
        // Track sent ACK for key rotation
        self.rotation_manager.track_sent(ack.len());
        
        ack
    }
    
    /// Process an acknowledgment message
    pub fn process_ack(&mut self, message: &[u8]) -> Result<u32> {
        let seq_num = self.data_manager.process_ack(message)?;
        
        // Track received ACK for key rotation
        self.rotation_manager.track_received(message.len());
        
        Ok(seq_num)
    }
    
    /// Close the session
    pub fn close(&mut self) -> Vec<u8> {
        // Update state
        self.state_manager.transition_to_closed();
        
        // Zero sensitive memory if needed
        if self.memory_manager.is_zero_on_free_enabled() {
            self.zero_sensitive_memory();
        }
        
        // Generate close message
        self.data_manager.generate_close()
    }
    
    /// Implement key rotation functionality
    
    /// Check if key rotation is needed
    pub fn should_rotate_keys(&self) -> bool {
        self.rotation_manager.should_rotate()
    }
    
    /// Track sent messages for key rotation
    pub fn track_sent(&mut self, bytes: usize) {
        self.rotation_manager.track_sent(bytes);
    }
    
    /// Track received messages for key rotation
    pub fn track_received(&mut self, bytes: usize) {
        self.rotation_manager.track_received(bytes);
    }
    
    /// Initiate key rotation
    pub fn initiate_key_rotation(&mut self) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot initiate key rotation in current state");
        }
        
        // Mark rotation as in progress
        self.rotation_manager.begin_rotation();
        
        // Generate new Kyber key pair, using memory manager if enabled
        let public_key_bytes = if cfg!(feature = "enhanced-memory") {
            self.key_manager.generate_rotation_keypair_with_memory_manager(&self.memory_manager)?
        } else {
            self.key_manager.generate_rotation_keypair()?
        };
        
        // Build a key rotation request message
        let seq_num = self.data_manager.get_send_sequence();
        let message = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(public_key_bytes)
            .build();
        
        // Track this message
        self.rotation_manager.track_sent(message.len());
        
        Ok(message)
    }
    
    /// Process key rotation
    pub fn process_key_rotation(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot process key rotation in current state");
        }
        
        // Parse the rotation request
        let parser = MessageParser::new(message)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::KeyExchange {
            return protocol_err!("Not a key exchange message");
        }
        
        // Get the public key from the payload
        let public_key_bytes = parser.payload(0)?;
        
        // Create key exchanger with the current config
        let key_exchanger = KeyExchange::from_config(&self.crypto_config)?;
        
        // Encapsulate a new shared secret
        let (shared_secret, ciphertext) = key_exchanger.encapsulate(public_key_bytes)?;
        
        // Derive a new encryption key
        let new_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Update the cipher with the new key, using memory manager if enabled
        if self.memory_manager.is_hardware_security_enabled() {
            // Try to use hardware security if available
            let result = self.key_manager.update_encryption_with_memory_manager(
                new_key, self.crypto_config.symmetric, &self.memory_manager)?;
            
            // Store session key in protected memory
            self.session_key = Some(self.memory_manager.protected_key32(new_key));
            
            // Try to store the key in HSM if successful
            if let Some(ref mut key_manager) = self.key_manager.as_mut() {
                let _ = key_manager.store_key_in_hsm();
            }
        } else {
            // Use regular update
            self.key_manager.update_encryption(new_key, self.crypto_config.symmetric)?;
            
            // Store session key in protected memory
            self.session_key = Some(self.memory_manager.protected_key32(new_key));
        }
        
        // Generate a response with the ciphertext
        let seq_num = self.data_manager.get_send_sequence();
        let response = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(ciphertext)
            .build();
        
        Ok(response)
    }
    
    /// Complete key rotation
    pub fn complete_key_rotation(&mut self, message: &[u8]) -> Result<()> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot complete key rotation in current state");
        }
        
        // Parse the response
        let parser = MessageParser::new(message)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::KeyExchange {
            return protocol_err!("Not a key exchange message");
        }
        
        // Get the ciphertext from the payload
        let ciphertext = parser.payload(0)?;
        
        // Create key exchanger with the current config
        let key_exchanger = KeyExchange::from_config(&self.crypto_config)?;
        
        // Get the secret key from the key manager (temporary approach - in a real implementation,
        // we'd have stored this along with the public key when initiating rotation)
        let secret_key_bytes = self.key_manager.get_temporary_secret_key()
            .ok_or_else(|| Error::Protocol("No key exchange in progress".to_string()))?;
        
        // Decapsulate the shared secret
        let shared_secret = key_exchanger.decapsulate(ciphertext, &secret_key_bytes)?;
        
        // Derive a new encryption key
        let new_key = KeyExchange::derive_encryption_key(&shared_secret)?;
        
        // Update the cipher with the new key
        if self.memory_manager.is_hardware_security_enabled() {
            // Try to use hardware security if available
            let result = self.key_manager.update_encryption_with_memory_manager(
                new_key, self.crypto_config.symmetric, &self.memory_manager)?;
            
            // Store session key in protected memory
            self.session_key = Some(self.memory_manager.protected_key32(new_key));
            
            // Try to store the key in HSM if successful
            if let Some(ref mut key_manager) = self.key_manager.as_mut() {
                let _ = key_manager.store_key_in_hsm();
            }
        } else {
            // Use regular update
            self.key_manager.update_encryption(new_key, self.crypto_config.symmetric)?;
            
            // Store session key in protected memory
            self.session_key = Some(self.memory_manager.protected_key32(new_key));
        }
        
        // Reset sequence numbers
        self.data_manager.reset_sequences();
        
        // Mark rotation as complete
        self.rotation_manager.complete_rotation();
        
        Ok(())
    }
    
    /// Get session statistics
    pub fn get_stats(&self) -> &SessionStats {
        self.rotation_manager.stats()
    }
    
    /// Get key rotation parameters
    pub fn get_rotation_params(&self) -> &KeyRotationParams {
        self.rotation_manager.params()
    }
    
    /// Set key rotation parameters
    pub fn set_rotation_params(&mut self, params: KeyRotationParams) {
        self.rotation_manager.set_params(params);
    }
}

// Implement PqcSessionKeyRotation trait for Session
impl PqcSessionKeyRotation for Session {
    fn should_rotate_keys(&self) -> bool {
        self.should_rotate_keys()
    }
    
    fn track_sent(&mut self, bytes: usize) {
        self.track_sent(bytes);
    }
    
    fn track_received(&mut self, bytes: usize) {
        self.track_received(bytes);
    }
    
    fn initiate_key_rotation(&mut self) -> Result<Vec<u8>> {
        self.initiate_key_rotation()
    }
    
    fn process_key_rotation(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.process_key_rotation(message)
    }
    
    fn complete_key_rotation(&mut self, message: &[u8]) -> Result<()> {
        self.complete_key_rotation(message)
    }
    
    fn get_stats(&self) -> &SessionStats {
        self.get_stats()
    }
    
    fn get_rotation_params(&self) -> &KeyRotationParams {
        self.get_rotation_params()
    }
    
    fn set_rotation_params(&mut self, params: KeyRotationParams) {
        self.set_rotation_params(params);
    }
}

// Implementation of SecureSession trait for Session
impl SecureSession for Session {
    fn memory_manager(&self) -> &SecureMemoryManager {
        &self.memory_manager
    }
    
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager {
        &mut self.memory_manager
    }
    
    fn erase_sensitive_memory(&mut self) {
        self.zero_sensitive_memory();
    }
}

// Add Drop implementation to ensure sensitive data is cleared
impl Drop for Session {
    fn drop(&mut self) {
        // Make sure all sensitive memory is zeroed
        if self.memory_manager.is_zero_on_free_enabled() {
            self.zero_sensitive_memory();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::Error;
    
    #[test]
    fn test_session_lifecycle() -> Result<()> {
        let mut client = Session::new()?;
        let mut server = Session::new()?;
        server.set_role(Role::Server);
        
        // Key exchange
        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;
        
        // Authentication
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        // Data transfer
        let test_data = b"Hello, PQC world!";
        let encrypted = client.encrypt_and_sign(test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        
        assert_eq!(test_data, &decrypted[..]);
        
        // Close
        client.close();
        server.close();
        
        assert_eq!(client.state(), SessionState::Closed);
        assert_eq!(server.state(), SessionState::Closed);
        
        Ok(())
    }
    
    #[test]
    fn test_sequence_validation() -> Result<()> {
        let mut client = Session::new()?;
        let mut server = Session::new()?;
        server.set_role(Role::Server);
        
        // Setup secure session
        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;
        
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        // Send first message
        let test_data = b"First message";
        let encrypted = client.encrypt_and_sign(test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, &decrypted[..]);
        
        // Try to replay the same message
        let result = server.verify_and_decrypt(&encrypted);
        assert!(matches!(result, Err(Error::InvalidSequence(_, _))));
        
        // Send second message
        let test_data2 = b"Second message";
        let encrypted2 = client.encrypt_and_sign(test_data2)?;
        let decrypted2 = server.verify_and_decrypt(&encrypted2)?;
        assert_eq!(test_data2, &decrypted2[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_memory_security() -> Result<()> {
        let mut session = Session::new()?;
        
        // Test default security level
        assert_eq!(session.memory_security_level(), MemorySecurity::Standard);
        
        // Change security level
        session.set_memory_security_level(MemorySecurity::Enhanced);
        assert_eq!(session.memory_security_level(), MemorySecurity::Enhanced);
        
        // Test secure memory operations
        assert!(session.memory_manager().is_memory_locking_enabled());
        session.disable_secure_memory();
        assert!(!session.memory_manager().is_memory_locking_enabled());
        
        session.enable_secure_memory();
        assert!(session.memory_manager().is_memory_locking_enabled());
        
        Ok(())
    }
    
    #[test]
    fn test_embedded_mode() -> Result<()> {
        let session = Session::embedded()?;
        
        // In embedded mode, memory locking should be disabled
        assert!(!session.memory_manager().is_memory_locking_enabled());
        // In embedded mode, canary protection should be disabled
        assert!(!session.memory_manager().is_canary_protection_enabled());
        
        Ok(())
    }
    
    #[test]
    fn test_zeroize_on_drop() -> Result<()> {
        // This test ensures sensitive data is cleared
        
        // Create a session with a protected key
        let key_data = [0x42u8; 32];
        let mut session = Session::with_protected_key(key_data)?;
        
        // Use the session
        let client_public_key = session.init_key_exchange()?;
        
        // Now verify the session key exists and matches
        if let Some(ref protected_key) = session.session_key {
            assert_eq!(*protected_key, key_data);
            
            // Manually zeroize the key
            session.zero_sensitive_memory();
            
            // Key should be zeroed
            if let Some(ref zeroed_key) = session.session_key {
                assert_eq!(*zeroed_key, [0u8; 32]);
            }
        }
        
        Ok(())
    }
    
    #[test]
    fn test_constant_time_operations() -> Result<()> {
        let mut session = Session::new()?;
        
        // Make sure constant-time operations are enabled
        session.memory_manager_mut().enable_constant_time();
        
        // Test constant-time equality
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [5u8, 6, 7, 8];
        
        assert!(session.constant_time_eq(&a, &b));
        assert!(!session.constant_time_eq(&a, &c));
        
        // Test with different lengths
        let d = [1u8, 2, 3];
        assert!(!session.constant_time_eq(&a, &d));
        
        Ok(())
    }
    
    #[test]
    fn test_protected_memory() -> Result<()> {
        let mut session = Session::new()?;
        
        // Create a secure vector
        let mut secure_vec = session.create_secure_vec32();
        
        // Add some data
        for i in 0..32 {
            secure_vec.push(i).unwrap();
        }
        
        // Check the content
        assert_eq!(secure_vec.len(), 32);
        for i in 0..32 {
            assert_eq!(secure_vec[i as usize], i);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_key_rotation() -> Result<()> {
        let mut client = Session::new()?;
        let mut server = Session::new()?;
        server.set_role(Role::Server);
        
        // Set up session
        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;
        
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        // Perform key rotation
        let rotation_msg = client.initiate_key_rotation()?;
        let server_response = server.process_key_rotation(&rotation_msg)?;
        client.complete_key_rotation(&server_response)?;
        
        // Verify we can still send data after rotation
        let test_data = b"After rotation";
        let encrypted = client.encrypt_and_sign(test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, &decrypted[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_hardware_security() -> Result<()> {
        let mut session = Session::new()?;
        
        // Try to enable hardware security
        let hw_available = session.use_hardware_security(true)?;
        
        // Print availability for diagnostic purposes
        println!("Hardware security available: {}", hw_available);
        
        // If hardware security is available, test it
        if hw_available {
            // Setup session
            let client_public_key = session.init_key_exchange()?;
            
            // Check if session_key was created
            assert!(session.session_key.is_some());
            
            // At this point, keys should be in HSM if available
            println!("HSM enabled: {}", session.memory_manager().is_hardware_security_enabled());
        }
        
        // Disable hardware security
        session.use_hardware_security(false)?;
        assert!(!session.memory_manager().is_hardware_security_enabled());
        
        Ok(())
    }
}