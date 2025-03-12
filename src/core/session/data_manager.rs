/*!
Data management for the PQC protocol.

This module provides functionality for encrypting, signing, decrypting,
and verifying data messages during the established session phase.
*/

use crate::core::{
    error::{Result, Error},
    message::{
        MessageType, 
        MessageBuilder, 
        MessageParser,
    },
    crypto::{Cipher, auth::Authentication},
    session::auth_manager::AuthManager,
    session::key_manager::KeyManager,
};
use crate::protocol_err;

use pqcrypto_traits::sign::DetachedSignature;
use std::sync::atomic::{AtomicU32, Ordering};

/// DataManager handles secure data transmission during the established phase
pub struct DataManager {
    /// Send sequence number
    send_sequence: AtomicU32,
    
    /// Receive sequence number
    recv_sequence: AtomicU32,
}

impl DataManager {
    /// Create a new data manager
    pub fn new() -> Self {
        Self {
            send_sequence: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
        }
    }
    
    /// Encrypt and sign data for sending
    pub fn encrypt_and_sign(
        &self,
        data: &[u8],
        key_manager: &KeyManager,
        auth_manager: &AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Get sequence number
        let seq_num = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create nonce
        let nonce = Cipher::create_nonce(seq_num, MessageType::Data);
        
        // Encrypt data
        let encrypted = cipher.encrypt(&nonce, data)?;
        
        // Sign the encrypted data
        let signature = auth_manager.sign(&encrypted);
        
        // Create message
        let message = MessageBuilder::new(MessageType::Data, seq_num)
            .with_payload(encrypted)
            .with_signature(signature.as_bytes().to_vec())
            .build();
        
        Ok(message)
    }
    
    /// Verify and decrypt received data
    pub fn verify_and_decrypt(
        &self,
        message: &[u8],
        key_manager: &KeyManager,
        auth_manager: &AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Parse message
        let parser = MessageParser::new(message)?;
        
        let header = parser.header();
        
        // Check sequence number
        let expected_seq = self.recv_sequence.load(Ordering::SeqCst);
        if header.seq_num != expected_seq {
            return Err(Error::InvalidSequence(expected_seq, header.seq_num));
        }
        
        // Get signature
        let signature = parser.signature(Authentication::signature_size())?;
        
        let signature = Authentication::signature_from_bytes(signature)?;
        
        // Get payload
        let encrypted = parser.payload(Authentication::signature_size())?;
        
        // Verify signature
        auth_manager.verify(encrypted, &signature)?;
        
        // Create nonce
        let nonce = Cipher::create_nonce(header.seq_num, header.msg_type);
        
        // Decrypt data
        let decrypted = cipher.decrypt(&nonce, encrypted)?;
        
        // Increment sequence number
        self.recv_sequence.fetch_add(1, Ordering::SeqCst);
        
        Ok(decrypted)
    }
    
    /// Generate an acknowledgment message
    pub fn generate_ack(&self, seq_num: u32) -> Vec<u8> {
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
        let parser = MessageParser::new(message)?;
        
        let header = parser.header();
        
        if header.msg_type != MessageType::Ack {
            return protocol_err!("Not an acknowledgment message");
        }
        
        let payload = parser.payload(0)?;
        
        if payload.len() != 4 {
            return protocol_err!("Invalid acknowledgment payload");
        }
        
        let mut buf = [0u8; 4];
        buf.copy_from_slice(payload);
        let seq_num = u32::from_be_bytes(buf);
        
        Ok(seq_num)
    }
    
    /// Reset sequence numbers
    /// This is useful during key rotation
    pub fn reset_sequences(&mut self) {
        self.send_sequence.store(0, Ordering::SeqCst);
        self.recv_sequence.store(0, Ordering::SeqCst);
    }
    
    /// Get the current send sequence number
    pub fn get_send_sequence(&self) -> u32 {
        self.send_sequence.load(Ordering::SeqCst)
    }
    
    /// Get the current receive sequence number
    pub fn get_recv_sequence(&self) -> u32 {
        self.recv_sequence.load(Ordering::SeqCst)
    }
    
    /// Generate a close message
    pub fn generate_close(&self) -> Vec<u8> {
        let close_seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);
        
        // Create close message
        MessageBuilder::new(MessageType::Close, close_seq)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::key_manager::KeyManager;
    use crate::core::session::auth_manager::AuthManager;
    
    // Helper to set up test session
    fn setup_test() -> Result<(KeyManager, KeyManager, AuthManager, AuthManager, DataManager, DataManager)> {
        // Create key managers
        let mut alice_key_manager = KeyManager::new();
        let mut bob_key_manager = KeyManager::new();
        
        // Set up key exchange
        let alice_pubkey = alice_key_manager.init_key_exchange()?;
        let ciphertext = bob_key_manager.accept_key_exchange(&alice_pubkey)?;
        alice_key_manager.process_key_exchange(&ciphertext)?;
        
        // Create auth managers
        let mut alice_auth_manager = AuthManager::new()?;
        let mut bob_auth_manager = AuthManager::new()?;
        
        // Exchange verification keys
        alice_auth_manager.set_remote_verification_key(bob_auth_manager.local_verification_key().clone())?;
        bob_auth_manager.set_remote_verification_key(alice_auth_manager.local_verification_key().clone())?;
        
        // Create data managers
        let alice_data_manager = DataManager::new();
        let bob_data_manager = DataManager::new();
        
        Ok((
            alice_key_manager, 
            bob_key_manager, 
            alice_auth_manager, 
            bob_auth_manager,
            alice_data_manager,
            bob_data_manager
        ))
    }
    
    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let (
            alice_key_manager, 
            bob_key_manager, 
            alice_auth_manager, 
            bob_auth_manager,
            alice_data_manager,
            bob_data_manager
        ) = setup_test()?;
        
        // Alice encrypts a message for Bob
        let message = b"Hello, Bob!";
        let encrypted = alice_data_manager.encrypt_and_sign(
            message, 
            &alice_key_manager, 
            &alice_auth_manager
        )?;
        
        // Bob decrypts and verifies the message
        let decrypted = bob_data_manager.verify_and_decrypt(
            &encrypted, 
            &bob_key_manager, 
            &bob_auth_manager
        )?;
        
        assert_eq!(message, &decrypted[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_sequence_numbers() -> Result<()> {
        let (
            alice_key_manager, 
            bob_key_manager, 
            alice_auth_manager, 
            bob_auth_manager,
            alice_data_manager,
            bob_data_manager
        ) = setup_test()?;
        
        // Send first message
        let message1 = b"First message";
        let encrypted1 = alice_data_manager.encrypt_and_sign(
            message1, 
            &alice_key_manager, 
            &alice_auth_manager
        )?;
        
        // Decrypt first message
        let decrypted1 = bob_data_manager.verify_and_decrypt(
            &encrypted1, 
            &bob_key_manager, 
            &bob_auth_manager
        )?;
        
        assert_eq!(message1, &decrypted1[..]);
        
        // Try to replay the first message (should fail)
        let result = bob_data_manager.verify_and_decrypt(
            &encrypted1, 
            &bob_key_manager, 
            &bob_auth_manager
        );
        
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSequence(_, _))));
        
        // Send second message
        let message2 = b"Second message";
        let encrypted2 = alice_data_manager.encrypt_and_sign(
            message2, 
            &alice_key_manager, 
            &alice_auth_manager
        )?;
        
        // Decrypt second message
        let decrypted2 = bob_data_manager.verify_and_decrypt(
            &encrypted2, 
            &bob_key_manager, 
            &bob_auth_manager
        )?;
        
        assert_eq!(message2, &decrypted2[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_ack_message() -> Result<()> {
        let (_, _, _, _, alice_data_manager, _) = setup_test()?;
        
        // Generate ACK for sequence number 42
        let ack_message = alice_data_manager.generate_ack(42);
        
        // Parse the ACK message
        let seq_num = alice_data_manager.process_ack(&ack_message)?;
        
        assert_eq!(seq_num, 42);
        
        Ok(())
    }
}