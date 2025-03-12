/*!
Session management for the PQC protocol.

This module provides the main session management class that handles the 
key exchange, authentication, and secure communication.
*/

use crate::{
    error::{Result, Error},
    constants::sizes,
    crypto::{
        KeyExchange, Cipher, Authentication,
        KyberPublicKey, KyberSecretKey, KyberCiphertext,
        DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
    },
    message::{
        MessageType, MessageBuilder, MessageParser,
    },
    memory::SecureMemory,
    security::rotation::{KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation},
};
// Import macros from the error module
use crate::{protocol_err, invalid_state_err, auth_err};

use std::sync::atomic::{AtomicU32, Ordering};
use pqcrypto_traits::kem::SharedSecret;
use pqcrypto_traits::sign::DetachedSignature;

use super::state::{StateManager, SessionState, Role};

/// Main session manager for the PQC protocol
pub struct SessionManager {
    /// State manager to track session progress
    state_manager: StateManager,

    /// Key rotation manager
    rotation_manager: KeyRotationManager,
    
    // Kyber key exchange pairs
    kyber_public_key: Option<KyberPublicKey>,
    kyber_secret_key: Option<SecureMemory<KyberSecretKey>>,
    
    // Dilithium signature pairs
    dilithium_public_key: DilithiumPublicKey,
    dilithium_secret_key: SecureMemory<DilithiumSecretKey>,
    remote_verification_key: Option<DilithiumPublicKey>,
    
    // Symmetric encryption
    encryption_key: Option<SecureMemory<[u8; sizes::chacha::KEY_SIZE]>>,
    cipher: Option<Cipher>,
    
    // Sequence tracking
    send_sequence: AtomicU32,
    recv_sequence: AtomicU32,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Result<Self> {
        // Generate Dilithium key pair
        let (dilithium_public_key, dilithium_secret_key) = Authentication::generate_keypair();
        
        let state_manager = StateManager::new(Role::Client);
        let rotation_manager = KeyRotationManager::new();
        
        Ok(Self {
            state_manager,
            rotation_manager,
            kyber_public_key: None,
            kyber_secret_key: None,
            dilithium_public_key,
            dilithium_secret_key: SecureMemory::new(dilithium_secret_key),
            remote_verification_key: None,
            encryption_key: None,
            cipher: None,
            send_sequence: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
        })
    }
    
    /// Set the role of this session (client or server)
    pub fn set_role(&mut self, role: Role) {
        self.state_manager.set_role(role);
    }
    
    /// Get the current session state
    pub fn state(&self) -> SessionState {
        self.state_manager.state()
    }
    
    /// Get the local verification key
    pub fn local_verification_key(&self) -> &DilithiumPublicKey {
        &self.dilithium_public_key
    }
    
    /// Initialize key exchange (client side)
    pub fn init_key_exchange(&mut self) -> Result<KyberPublicKey> {
        if !self.state_manager.can_init_key_exchange() {
            return invalid_state_err!(
                "can initialize key exchange",
                format!("{:?}", self.state_manager.state())
            );
        }
        
        // Generate key pair
        let (public_key, secret_key) = KeyExchange::generate_keypair();
        
        // Store keys, wrapping the secret key in SecureMemory
        self.kyber_public_key = Some(public_key.clone());
        self.kyber_secret_key = Some(SecureMemory::new(secret_key));
        
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
        
        // Encapsulate shared secret
        let (shared_secret, ciphertext) = KeyExchange::encapsulate(client_public_key);
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(shared_secret.as_bytes())
            .map_err(|e| e)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
        self.cipher = Some(Cipher::new(&*self.encryption_key.as_ref().unwrap()));
        
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
        
        let secure_kyber_secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Secret key not available".into()))?;
        
        // Decapsulate shared secret using the underlying key from SecureMemory
        let shared_secret = KeyExchange::decapsulate(ciphertext, &*secure_kyber_secret_key);
        
        // Derive encryption key
        let encryption_key = KeyExchange::derive_encryption_key(shared_secret.as_bytes())
            .map_err(|e| e)?;
        
        // Wrap the encryption key with SecureMemory and initialize the cipher
        self.encryption_key = Some(SecureMemory::new(encryption_key));
        self.cipher = Some(Cipher::new(&*self.encryption_key.as_ref().unwrap()));
        
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
        
        self.remote_verification_key = Some(key);
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
        
        if self.remote_verification_key.is_none() {
            return auth_err!(crate::error::AuthError::MissingVerificationKey);
        }
        
        // At this point, we would normally verify a challenge.
        // For now, we'll just transition to the established state.
        self.state_manager.transition_to_established();
        
        // Reset key rotation stats when authentication is completed
        self.rotation_manager.reset_stats();
        
        Ok(())
    }
    
    /// Encrypt and sign data
    pub fn encrypt_and_sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot transfer data in current state");
        }
        
        // Check if key rotation is needed
        if self.should_rotate_keys() {
            // In production, we would handle rotation here
            // For now, just track that we detected the need
            log::info!("Key rotation needed, but not implemented yet");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        // Get sequence number
        let seq_num = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create nonce
        let nonce = Cipher::create_nonce(seq_num, MessageType::Data);
        
        // Encrypt data
        let encrypted = cipher.encrypt(&nonce, data)
            .map_err(|e| e)?;
        
        // Sign the encrypted data.
        // Dereference the SecureMemory to pass the underlying secret key.
        let signature = Authentication::sign(&encrypted, &*self.dilithium_secret_key);
        
        // Create message
        let message = MessageBuilder::new(MessageType::Data, seq_num)
            .with_payload(encrypted)
            .with_signature(signature.as_bytes().to_vec())
            .build();
        
        // Track sent message for key rotation
        self.rotation_manager.track_sent(message.len());
        
        Ok(message)
    }
    
    /// Verify and decrypt data
    pub fn verify_and_decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot transfer data in current state");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication(crate::error::AuthError::MissingVerificationKey))?;
        
        // Parse message
        let parser = MessageParser::new(message)
            .map_err(|e| e)?;
        
        let header = parser.header();
        
        // Check sequence number
        let expected_seq = self.recv_sequence.load(Ordering::SeqCst);
        if header.seq_num != expected_seq {
            return Err(Error::InvalidSequence(expected_seq, header.seq_num));
        }
        
        // Get signature
        let signature = parser.signature(Authentication::signature_size())
            .map_err(|e| e)?;
        
        let signature = Authentication::signature_from_bytes(signature)
            .map_err(|e| e)?;
        
        // Get payload
        let encrypted = parser.payload(Authentication::signature_size())
            .map_err(|e| e)?;
        
        // Verify signature
        Authentication::verify(encrypted, &signature, verification_key)
            .map_err(|e| e)?;
        
        // Create nonce
        let nonce = Cipher::create_nonce(header.seq_num, header.msg_type);
        
        // Decrypt data
        let decrypted = cipher.decrypt(&nonce, encrypted)
            .map_err(|e| e)?;
        
        // Increment sequence number
        self.recv_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Track received message for key rotation
        self.rotation_manager.track_received(message.len());
        
        Ok(decrypted)
    }
    
    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<DilithiumSignature> {
        // Dereference the secure secret key for signing
        Ok(Authentication::sign(data, &*self.dilithium_secret_key))
    }
    
    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &DilithiumSignature) -> Result<()> {
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication(crate::error::AuthError::MissingVerificationKey))?;
        
        Authentication::verify(data, signature, verification_key)
    }
    
    /// Generate an acknowledgment message
    pub fn generate_ack(&mut self, seq_num: u32) -> Vec<u8> {
        let ack_seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create message with the ACK sequence number as payload
        let payload = seq_num.to_be_bytes().to_vec();
        
        let message = MessageBuilder::new(MessageType::Ack, ack_seq)
            .with_payload(payload)
            .build();
            
        // Track sent ACK for key rotation
        self.rotation_manager.track_sent(message.len());
        
        message
    }
    
    /// Process an acknowledgment message
    pub fn process_ack(&mut self, message: &[u8]) -> Result<u32> {
        // Parse message
        let parser = MessageParser::new(message)
            .map_err(|e| e)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::Ack {
            return protocol_err!("Not an acknowledgment message");
        }
        
        let payload = parser.payload(0)
            .map_err(|e| e)?;
        
        if payload.len() != 4 {
            return protocol_err!("Invalid acknowledgment payload");
        }
        
        let mut buf = [0u8; 4];
        buf.copy_from_slice(payload);
        let seq_num = u32::from_be_bytes(buf);
        
        // Track received ACK for key rotation
        self.rotation_manager.track_received(message.len());
        
        Ok(seq_num)
    }
    
    /// Close the session
    pub fn close(&mut self) -> Vec<u8> {
        let close_seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Update state
        self.state_manager.transition_to_closed();
        
        // Create close message
        MessageBuilder::new(MessageType::Close, close_seq)
            .build()
    }
}

// Implement PqcSessionKeyRotation for SessionManager
impl PqcSessionKeyRotation for SessionManager {
    fn should_rotate_keys(&self) -> bool {
        self.rotation_manager.should_rotate()
    }
    
    fn track_sent(&mut self, bytes: usize) {
        self.rotation_manager.track_sent(bytes);
    }
    
    fn track_received(&mut self, bytes: usize) {
        self.rotation_manager.track_received(bytes);
    }
    
    fn initiate_key_rotation(&mut self) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot initiate key rotation in current state");
        }
        
        // Mark rotation as in progress
        self.rotation_manager.begin_rotation();
        
        // Generate new Kyber key pair
        let (public_key, secret_key) = KeyExchange::generate_keypair();
        
        // Store the new public key - we'll keep the old keys until rotation completes
        let new_public_key = public_key.clone();
        
        // Build a key rotation request message
        let seq_num = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        let message = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(public_key.as_bytes().to_vec())
            .build();
        
        // Track this message
        self.rotation_manager.track_sent(message.len());
        
        Ok(message)
    }
    
    fn process_key_rotation(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        // This implementation is a placeholder - in a production system, 
        // you would implement full key rotation logic here.
        // For now, we'll just acknowledge the request
        
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot process key rotation in current state");
        }
        
        // Parse the rotation request
        let parser = MessageParser::new(message)
            .map_err(|e| e)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::KeyExchange {
            return protocol_err!("Not a key exchange message");
        }
        
        // The real implementation would process the new public key and generate
        // a proper response. For now, just return a dummy response.
        
        let seq_num = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        let response = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(vec![0u8; 10]) // Dummy payload
            .build();
        
        Ok(response)
    }
    
    fn complete_key_rotation(&mut self, message: &[u8]) -> Result<()> {
        // Placeholder implementation - this would handle switching to new keys
        
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot complete key rotation in current state");
        }
        
        // Mark rotation as complete
        self.rotation_manager.complete_rotation();
        
        Ok(())
    }
    
    fn get_stats(&self) -> &SessionStats {
        self.rotation_manager.stats()
    }
    
    fn get_rotation_params(&self) -> &KeyRotationParams {
        self.rotation_manager.params()
    }
    
    fn set_rotation_params(&mut self, params: KeyRotationParams) {
        self.rotation_manager.set_params(params);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_lifecycle() -> Result<()> {
        let mut client = SessionManager::new()?;
        let mut server = SessionManager::new()?;
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
        let mut client = SessionManager::new()?;
        let mut server = SessionManager::new()?;
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
    fn test_key_rotation() -> Result<()> {
        let mut client = SessionManager::new()?;
        let mut server = SessionManager::new()?;
        server.set_role(Role::Server);
        
        // Setup secure session
        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;
        
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        // Set custom rotation parameters for testing (very low thresholds)
        let test_params = KeyRotationParams {
            rotation_interval: Duration::from_secs(3600), // 1 hour
            max_messages: 3, // Rotate after 3 messages
            max_bytes: 1000, // Rotate after 1KB
            rotate_on_error: true,
        };
        
        client.set_rotation_params(test_params);
        
        // Send messages to trigger rotation
        for i in 0..3 {
            let test_data = format!("Message {}", i).into_bytes();
            let encrypted = client.encrypt_and_sign(&test_data)?;
            let decrypted = server.verify_and_decrypt(&encrypted)?;
            assert_eq!(test_data, decrypted);
        }
        
        // Check if rotation is needed (should be true after 3 messages)
        assert!(client.should_rotate_keys());
        
        // Initiate rotation
        let rotation_request = client.initiate_key_rotation()?;
        
        // Process rotation on server
        let rotation_response = server.process_key_rotation(&rotation_request)?;
        
        // Complete rotation on client
        client.complete_key_rotation(&rotation_response)?;
        
        // Verify rotation was completed by checking stats reset
        assert_eq!(client.get_stats().messages_sent, 0);
        
        // Test that communication still works after rotation
        let test_data = b"Post-rotation message";
        let encrypted = client.encrypt_and_sign(test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, &decrypted[..]);
        
        Ok(())
    }
}