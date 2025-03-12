/*!
Main session implementation for the PQC protocol.

This module integrates the different components (key management, authentication,
data handling) to provide a complete session implementation.

The Session is the main entry point for using the PQC protocol. It handles
the key exchange, authentication, and secure data transfer between parties.
*/

use crate::core::{
    error::{Result, AuthError},
    session::{
        state::{StateManager, SessionState, Role},
        key_manager::KeyManager,
        auth_manager::AuthManager,
        data_manager::DataManager,
    },
    security::rotation::{KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation},
    crypto::{
        key_exchange::KeyExchange,
        KyberPublicKey, 
        KyberCiphertext,
        DilithiumPublicKey,
    },
    message::{MessageType, MessageBuilder, MessageParser},
};
use crate::{invalid_state_err, auth_err, protocol_err};

/// Main session for the PQC protocol
pub struct Session {
    /// Manages session state
    state_manager: StateManager,
    
    /// Manages key exchange and encryption
    key_manager: KeyManager,
    
    /// Manages authentication and signatures
    auth_manager: AuthManager,
    
    /// Manages data operations
    data_manager: DataManager,
    
    /// Manages key rotation
    rotation_manager: KeyRotationManager,
}

impl Session {
    /// Create a new session
    pub fn new() -> Result<Self> {
        let state_manager = StateManager::new(Role::Client);
        let key_manager = KeyManager::new();
        let auth_manager = AuthManager::new()?;
        let data_manager = DataManager::new();
        let rotation_manager = KeyRotationManager::new();
        
        Ok(Self {
            state_manager,
            key_manager,
            auth_manager,
            data_manager,
            rotation_manager,
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
        let public_key = self.key_manager.init_key_exchange()?;
        
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
        let ciphertext = self.key_manager.accept_key_exchange(client_public_key)?;
        
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
        self.key_manager.process_key_exchange(ciphertext)?;
        
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
            // In production, we would handle rotation here
            // For now, just track that we detected the need
            // Replacing log::info with a comment for now
            // log::info!("Key rotation needed, but not implemented yet");
        }
        
        // Encrypt and sign the data
        let message = self.data_manager.encrypt_and_sign(
            data, 
            &self.key_manager, 
            &self.auth_manager
        )?;
        
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
        
        // Verify and decrypt the message
        let decrypted = self.data_manager.verify_and_decrypt(
            message, 
            &self.key_manager, 
            &self.auth_manager
        )?;
        
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
        
        // Generate new Kyber key pair
        let (public_key, _) = KeyExchange::generate_keypair();
        
        // Build a key rotation request message
        let seq_num = self.data_manager.get_send_sequence();
        let message = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(public_key.as_bytes().to_vec())
            .build();
        
        // Track this message
        self.rotation_manager.track_sent(message.len());
        
        Ok(message)
    }
    
    /// Process key rotation
    pub fn process_key_rotation(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        // This implementation is a placeholder - in a production system, 
        // you would implement full key rotation logic here.
        
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot process key rotation in current state");
        }
        
        // Parse the rotation request
        let parser = MessageParser::new(message)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::KeyExchange {
            return protocol_err!("Not a key exchange message");
        }
        
        // The real implementation would process the new public key and generate
        // a proper response. For now, just return a dummy response.
        
        let seq_num = self.data_manager.get_send_sequence();
        let response = MessageBuilder::new(MessageType::KeyExchange, seq_num)
            .with_payload(vec![0u8; 10]) // Dummy payload
            .build();
        
        Ok(response)
    }
    
    /// Complete key rotation
    pub fn complete_key_rotation(&mut self, _message: &[u8]) -> Result<()> {
        // Placeholder implementation - this would handle switching to new keys
        
        if !self.state_manager.can_transfer_data() {
            return protocol_err!("Cannot complete key rotation in current state");
        }
        
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

#[cfg(test)]
mod tests {
    use super::*;
    
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
}