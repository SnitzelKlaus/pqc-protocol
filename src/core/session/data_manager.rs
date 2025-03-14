/*!
Data management for the PQC protocol with enhanced security.

This module provides functionality for encrypting, signing, decrypting,
and verifying data messages during the established session phase,
with enhancements for timing attack prevention and memory security.
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
    security::constant_time::{constant_time_eq, constant_time_increment},
    constants::features,
};
use crate::protocol_err;

use pqcrypto_traits::sign::DetachedSignature;
use std::sync::atomic::{AtomicU32, Ordering};

// Add new imports for enhanced security
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;
use crate::core::memory::protected_memory::ProtectedMemory;
use crate::core::memory::heapless_vec::SecureHeaplessVec;
use subtle::ConstantTimeEq;

/// DataManager handles secure data transmission during the established phase
pub struct DataManager {
    /// Send sequence number
    send_sequence: AtomicU32,
    
    /// Receive sequence number
    recv_sequence: AtomicU32,
    
    /// Whether to use constant-time operations
    use_constant_time: bool,
}

impl DataManager {
    /// Create a new data manager
    pub fn new() -> Self {
        Self {
            send_sequence: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
            use_constant_time: true,
        }
    }
    
    /// Enable constant-time operations
    pub fn enable_constant_time(&mut self) {
        self.use_constant_time = true;
    }
    
    /// Disable constant-time operations
    pub fn disable_constant_time(&mut self) {
        self.use_constant_time = false;
    }
    
    /// Encrypt and sign data for sending
    pub fn encrypt_and_sign<T: AsRef<[u8]>>(
        &self,
        data: T,
        key_manager: &KeyManager,
        auth_manager: &AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Get sequence number using constant-time operations if enabled
        let seq_num = if self.use_constant_time || features::CONSTANT_TIME {
            let mut seq = 0u32;
            constant_time_increment(&mut seq, self.send_sequence.fetch_add(1, Ordering::SeqCst));
            seq
        } else {
            self.send_sequence.fetch_add(1, Ordering::SeqCst)
        };
        
        // Create nonce
        let nonce = Cipher::create_nonce(seq_num, MessageType::Data);
        
        // Encrypt data
        let encrypted = cipher.encrypt(&nonce, data.as_ref())?;
        
        // Sign the encrypted data
        let signature = auth_manager.sign(&encrypted)?;
        
        // Create message
        let message = MessageBuilder::new(MessageType::Data, seq_num)
            .with_payload(encrypted)
            .with_signature(signature.as_bytes().to_vec())
            .build();
        
        Ok(message)
    }
    
    /// Verify and decrypt received data
    pub fn verify_and_decrypt<T: AsRef<[u8]>>(
        &self,
        message: T,
        key_manager: &KeyManager,
        auth_manager: &AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Parse message
        let parser = MessageParser::new(message.as_ref())?;
        
        let header = parser.header();
        
        // Check sequence number using constant-time comparison
        let expected_seq = self.recv_sequence.load(Ordering::SeqCst);
        if self.use_constant_time || features::CONSTANT_TIME {
            // Use constant-time comparison to avoid timing attacks
            if !u32::from_ne_bytes(expected_seq.to_ne_bytes())
                 .ct_eq(&u32::from_ne_bytes(header.seq_num.to_ne_bytes()))
                 .into()
            {
                return Err(Error::InvalidSequence(expected_seq, header.seq_num));
            }
        } else {
            // Use regular comparison
            if header.seq_num != expected_seq {
                return Err(Error::InvalidSequence(expected_seq, header.seq_num));
            }
        }
        
        // Get the signature size from auth_manager
        let signature_size = auth_manager.signature_size();
        
        // Get signature
        let signature_bytes = parser.signature(signature_size)?;
        
        // Convert bytes to signature using auth_manager's algorithm
        let signature = auth_manager.signature_from_bytes(signature_bytes)?;
        
        // Get payload
        let encrypted = parser.payload(signature_size)?;
        
        // Verify signature
        auth_manager.verify(encrypted, &signature)?;
        
        // Create nonce
        let nonce = Cipher::create_nonce(header.seq_num, header.msg_type);
        
        // Decrypt data
        let decrypted = cipher.decrypt(&nonce, encrypted)?;
        
        // Increment sequence number in constant time
        if self.use_constant_time || features::CONSTANT_TIME {
            let mut seq = expected_seq;
            constant_time_increment(&mut seq, 1);
            self.recv_sequence.store(seq, Ordering::SeqCst);
        } else {
            self.recv_sequence.fetch_add(1, Ordering::SeqCst);
        }
        
        Ok(decrypted)
    }
    
    /// Generate an acknowledgment message
    pub fn generate_ack(&self, seq_num: u32) -> Vec<u8> {
        // Get next sequence number
        let ack_seq = if self.use_constant_time || features::CONSTANT_TIME {
            let mut seq = 0u32;
            constant_time_increment(&mut seq, self.send_sequence.fetch_add(1, Ordering::SeqCst));
            seq
        } else {
            self.send_sequence.fetch_add(1, Ordering::SeqCst)
        };
        
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
    
    /// Enhanced encrypt_and_sign that uses constant-time operations
    pub fn encrypt_and_sign_constant_time<T: AsRef<[u8]>>(
        &self,
        data: T,
        key_manager: &mut KeyManager,
        auth_manager: &mut AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Get sequence number using constant-time operations
        let mut seq = 0u32;
        constant_time_increment(&mut seq, self.send_sequence.fetch_add(1, Ordering::SeqCst));
        
        // Create nonce
        let nonce = Cipher::create_nonce(seq, MessageType::Data);
        
        // Encrypt data - wrap in ZeroizeOnDrop to ensure data is cleared
        let encrypted = ZeroizeOnDrop::new(cipher.encrypt(&nonce, data.as_ref())?);
        
        // Sign the encrypted data
        let signature = auth_manager.sign(&encrypted)?;
        
        // Create message
        let message = MessageBuilder::new(MessageType::Data, seq)
            .with_payload(encrypted.into_inner())
            .with_signature(signature.as_bytes().to_vec())
            .build();
        
        Ok(message)
    }
    
    /// Enhanced verify_and_decrypt that uses constant-time operations
    pub fn verify_and_decrypt_constant_time<T: AsRef<[u8]>>(
        &self,
        message: T,
        key_manager: &mut KeyManager,
        auth_manager: &mut AuthManager,
    ) -> Result<Vec<u8>> {
        let cipher = key_manager.get_cipher()?;
        
        // Parse message
        let parser = MessageParser::new(message.as_ref())?;
        
        let header = parser.header();
        
        // Check sequence number using constant-time comparison
        let expected_seq = self.recv_sequence.load(Ordering::SeqCst);
        
        // Use constant-time comparison to avoid timing attacks
        if !u32::from_ne_bytes(expected_seq.to_ne_bytes())
             .ct_eq(&u32::from_ne_bytes(header.seq_num.to_ne_bytes()))
             .into()
        {
            return Err(Error::InvalidSequence(expected_seq, header.seq_num));
        }
        
        // Get the signature size from auth_manager
        let signature_size = auth_manager.signature_size();
        
        // Get signature
        let signature_bytes = parser.signature(signature_size)?;
        
        // Convert bytes to signature using auth_manager's algorithm
        let signature = auth_manager.signature_from_bytes(signature_bytes)?;
        
        // Get payload
        let encrypted = parser.payload(signature_size)?;
        
        // Verify signature
        auth_manager.verify(encrypted, &signature)?;
        
        // Create nonce
        let nonce = Cipher::create_nonce(header.seq_num, header.msg_type);
        
        // Decrypt data and wrap in ZeroizeOnDrop
        let decrypted = ZeroizeOnDrop::new(cipher.decrypt(&nonce, encrypted)?);
        
        // Increment sequence number in constant time
        let mut seq = expected_seq;
        constant_time_increment(&mut seq, 1);
        self.recv_sequence.store(seq, Ordering::SeqCst);
        
        // Return the decrypted data (consuming ZeroizeOnDrop)
        Ok(decrypted.into_inner())
    }
}

impl Default for DataManager {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Drop to ensure proper cleanup
impl Drop for DataManager {
    fn drop(&mut self) {
        // Reset sequence numbers on drop
        self.reset_sequences();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
    fn test_constant_time_operations() -> Result<()> {
        let (
            mut alice_key_manager, 
            mut bob_key_manager, 
            mut alice_auth_manager, 
            mut bob_auth_manager,
            mut alice_data_manager,
            mut bob_data_manager
        ) = setup_test()?;
        
        // Enable constant-time operations
        alice_data_manager.enable_constant_time();
        bob_data_manager.enable_constant_time();
        
        // Alice encrypts a message for Bob using constant-time operations
        let message = b"Hello, Bob! This is a constant-time message.";
        let encrypted = alice_data_manager.encrypt_and_sign_constant_time(
            message, 
            &mut alice_key_manager, 
            &mut alice_auth_manager
        )?;
        
        // Bob decrypts and verifies the message
        let decrypted = bob_data_manager.verify_and_decrypt_constant_time(
            &encrypted, 
            &mut bob_key_manager, 
            &mut bob_auth_manager
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
    fn test_with_heapless_vec() -> Result<()> {
        let (
            alice_key_manager, 
            bob_key_manager, 
            alice_auth_manager, 
            bob_auth_manager,
            alice_data_manager,
            bob_data_manager
        ) = setup_test()?;
        
        // Create a message using a stack-allocated vector
        let mut message_stack = SecureHeaplessVec::<u8, 32>::new();
        for byte in b"Hello from stack memory!" {
            let _ = message_stack.push(*byte);
        }
        
        // Alice encrypts the stack-allocated message for Bob
        let encrypted = alice_data_manager.encrypt_and_sign(
            &message_stack, 
            &alice_key_manager, 
            &alice_auth_manager
        )?;
        
        // Bob decrypts and verifies the message
        let decrypted = bob_data_manager.verify_and_decrypt(
            &encrypted, 
            &bob_key_manager, 
            &bob_auth_manager
        )?;
        
        assert_eq!(&message_stack[..], &decrypted[..]);
        
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