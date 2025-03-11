/*!
Session management for the PQC protocol.

This module provides the main session management class that handles the 
key exchange, authentication, and secure communication.
*/

use crate::{
    error::{Result, Error, key_exchange_err, auth_err, protocol_err},
    constants::sizes,
    crypto::{
        KeyExchange, Cipher, Authentication,
        KyberPublicKey, KyberSecretKey, KyberCiphertext,
        DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
    },
    message::{
        MessageType, MessageBuilder, MessageParser,
    },
};


use std::sync::atomic::{AtomicU32, Ordering};
use pqcrypto_traits::kem::
    SharedSecret
;
use pqcrypto_traits::sign::
    DetachedSignature
;

use super::state::{StateManager, SessionState, Role};

/// Main session manager for the PQC protocol
pub struct SessionManager {
    /// State manager to track session progress
    state_manager: StateManager,
    
    // Kyber key exchange pairs
    kyber_public_key: Option<KyberPublicKey>,
    kyber_secret_key: Option<KyberSecretKey>,
    
    // Dilithium signature pairs
    dilithium_public_key: DilithiumPublicKey,
    dilithium_secret_key: DilithiumSecretKey,
    remote_verification_key: Option<DilithiumPublicKey>,
    
    // Symmetric encryption
    encryption_key: Option<[u8; sizes::chacha::KEY_SIZE]>,
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
        
        Ok(Self {
            state_manager,
            kyber_public_key: None,
            kyber_secret_key: None,
            dilithium_public_key,
            dilithium_secret_key,
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
            return key_exchange_err("Cannot initialize key exchange in current state");
        }
        
        // Generate key pair
        let (public_key, secret_key) = KeyExchange::generate_keypair();
        
        // Store keys
        self.kyber_public_key = Some(public_key.clone());
        self.kyber_secret_key = Some(secret_key);
        
        // Update state
        self.state_manager.transition_to_key_exchange_initiated();
        
        Ok(public_key)
    }
    
    /// Accept key exchange (server side)
    pub fn accept_key_exchange(&mut self, client_public_key: &KyberPublicKey) -> Result<KyberCiphertext> {
        if !self.state_manager.can_accept_key_exchange() {
            return key_exchange_err("Cannot accept key exchange in current state");
        }
        
        // Encapsulate shared secret
        let (shared_secret, ciphertext) = KeyExchange::encapsulate(client_public_key);
        
        // Derive encryption key
        let encryption_key = match KeyExchange::derive_encryption_key(shared_secret.as_bytes()) {
            Ok(key) => key,
            Err(e) => return Err(e),
        };
        
        // Initialize cipher
        self.encryption_key = Some(encryption_key);
        self.cipher = Some(Cipher::new(&encryption_key));
        
        // Update state
        self.state_manager.transition_to_key_exchange_completed();
        
        Ok(ciphertext)
    }
    
    /// Process key exchange response (client side)
    pub fn process_key_exchange(&mut self, ciphertext: &KyberCiphertext) -> Result<()> {
        if !self.state_manager.can_process_key_exchange() {
            return key_exchange_err("Cannot process key exchange in current state");
        }
        
        let secret_key = self.kyber_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Secret key not available".into()))?;
        
        // Decapsulate shared secret
        let shared_secret = KeyExchange::decapsulate(ciphertext, secret_key);
        
        // Derive encryption key
        let encryption_key = match KeyExchange::derive_encryption_key(shared_secret.as_bytes()) {
            Ok(key) => key,
            Err(e) => return Err(e),
        };
        
        // Initialize cipher
        self.encryption_key = Some(encryption_key);
        self.cipher = Some(Cipher::new(&encryption_key));
        
        // Update state
        self.state_manager.transition_to_key_exchange_completed();
        
        Ok(())
    }
    
    /// Set the remote verification key
    pub fn set_remote_verification_key(&mut self, key: DilithiumPublicKey) -> Result<()> {
        if !self.state_manager.can_set_verification_key() {
            return auth_err("Cannot set verification key in current state");
        }
        
        self.remote_verification_key = Some(key);
        self.state_manager.transition_to_authentication_initiated();
        
        Ok(())
    }
    
    /// Complete authentication
    pub fn complete_authentication(&mut self) -> Result<()> {
        if !self.state_manager.can_complete_authentication() {
            return auth_err("Cannot complete authentication in current state");
        }
        
        if self.remote_verification_key.is_none() {
            return auth_err("Remote verification key not set");
        }
        
        // At this point, we would normally verify a challenge
        // For now, we'll just transition to the established state
        self.state_manager.transition_to_established();
        
        Ok(())
    }
    
    /// Encrypt and sign data
    pub fn encrypt_and_sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err("Cannot transfer data in current state");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        // Get sequence number
        let seq_num = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create nonce
        let nonce = Cipher::create_nonce(seq_num, MessageType::Data);
        
        // Encrypt data
        let encrypted = match cipher.encrypt(&nonce, data) {
            Ok(e) => e,
            Err(e) => return Err(e),
        };
        
        // Sign the encrypted data
        let signature = Authentication::sign(&encrypted, &self.dilithium_secret_key);
        
        // Create message
        let message = MessageBuilder::new(MessageType::Data, seq_num)
            .with_payload(encrypted)
            .with_signature(signature.as_bytes().to_vec())
            .build();
        
        Ok(message)
    }
    
    /// Verify and decrypt data
    pub fn verify_and_decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if !self.state_manager.can_transfer_data() {
            return protocol_err("Cannot transfer data in current state");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication("Remote verification key not set".into()))?;
        
        // Parse message
        let parser = match MessageParser::new(message) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        
        let header = parser.header();
        
        // Check sequence number
        let expected_seq = self.recv_sequence.load(Ordering::SeqCst);
        if header.seq_num != expected_seq {
            return Err(Error::InvalidSequence);
        }
        
        // Get signature
        let signature = match parser.signature(Authentication::signature_size()) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        let signature = match Authentication::signature_from_bytes(signature) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        
        // Get payload
        let encrypted = match parser.payload(Authentication::signature_size()) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        
        // Verify signature
        match Authentication::verify(encrypted, &signature, verification_key) {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Create nonce
        let nonce = Cipher::create_nonce(header.seq_num, header.msg_type);
        
        // Decrypt data
        let decrypted = match cipher.decrypt(&nonce, encrypted) {
            Ok(d) => d,
            Err(e) => return Err(e),
        };
        
        // Increment sequence number
        self.recv_sequence.fetch_add(1, Ordering::SeqCst);
        
        Ok(decrypted)
    }
    
    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Result<DilithiumSignature> {
        Ok(Authentication::sign(data, &self.dilithium_secret_key))
    }
    
    /// Verify a signature
    pub fn verify(&self, data: &[u8], signature: &DilithiumSignature) -> Result<()> {
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication("Remote verification key not set".into()))?;
        
        Authentication::verify(data, signature, verification_key)
    }
    
    /// Generate an acknowledgment message
    pub fn generate_ack(&mut self, seq_num: u32) -> Vec<u8> {
        let ack_seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create message with the ACK sequence number as payload
        let payload = seq_num.to_be_bytes().to_vec();
        
        MessageBuilder::new(MessageType::Ack, ack_seq)
            .with_payload(payload)
            .build()
    }
    
    /// Process an acknowledgment message
    pub fn process_ack(&self, message: &[u8]) -> Result<u32> {
        // Parse message
        let parser = match MessageParser::new(message) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        
        let header = parser.header();
        
        if header.msg_type != MessageType::Ack {
            return protocol_err("Not an acknowledgment message");
        }
        
        let payload = match parser.payload(0) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        
        if payload.len() != 4 {
            return protocol_err("Invalid acknowledgment payload");
        }
        
        let mut buf = [0u8; 4];
        buf.copy_from_slice(payload);
        let seq_num = u32::from_be_bytes(buf);
        
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
        assert!(matches!(result, Err(Error::InvalidSequence)));
        
        // Send second message
        let test_data2 = b"Second message";
        let encrypted2 = client.encrypt_and_sign(test_data2)?;
        let decrypted2 = server.verify_and_decrypt(&encrypted2)?;
        assert_eq!(test_data2, &decrypted2[..]);
        
        Ok(())
    }
}