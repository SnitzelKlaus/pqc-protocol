/*!
Synchronous client implementation for the PQC protocol.

This module provides the client-side operations for the synchronous API.
*/

use crate::{
    error::Result,
    session::{PqcSession, Role, SessionState},
    security::rotation::PqcSessionKeyRotation,
    constants::MAX_CHUNK_SIZE,
};

// Required traits for from_bytes/as_bytes methods
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, Ciphertext as KemCiphertext};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;

use super::stream::{PqcSyncStreamSender, PqcSyncStreamReceiver};

/// Client-side operations for the PQC protocol
pub struct PqcClient {
    /// The underlying session
    session: PqcSession,
}

impl PqcClient {
    /// Create a new PQC client
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Client);
        Ok(Self { session })
    }
    
    /// Start the connection process
    ///
    /// Initiates key exchange and returns the public key to send to the server.
    pub fn connect(&mut self) -> Result<Vec<u8>> {
        let public_key = self.session.init_key_exchange()?;
        Ok(public_key.as_bytes().to_vec())
    }
    
    /// Process the server's response to complete the connection
    ///
    /// Takes the ciphertext from the server and returns the verification key to send.
    pub fn process_response(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Convert bytes to Kyber ciphertext
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| {
                crate::crypto_err!(crate::error::CryptoError::InvalidKeyFormat)
            })?;
        
        // Process the ciphertext
        match self.session.process_key_exchange(&ct) {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Return the verification key
        Ok(self.session.local_verification_key().as_bytes().to_vec())
    }
    
    /// Complete authentication with the server's verification key
    ///
    /// Takes the server's verification key and completes the connection.
    pub fn authenticate(&mut self, server_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(server_verification_key)
            .map_err(|_| {
                crate::auth_err!(crate::error::AuthError::InvalidKeyFormat)
            })?;
        
        // Set the remote verification key
        self.session.set_remote_verification_key(vk)?;
        
        // Complete authentication
        match self.session.complete_authentication() {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        Ok(())
    }
    
    /// Send a message to the server
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let result = self.session.encrypt_and_sign(data)?;
        
        // Track sent data for key rotation if enabled
        if self.session.should_rotate_keys() {
            self.session.track_sent(result.len());
        }
        
        Ok(result)
    }
    
    /// Receive a message from the server
    pub fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let result = self.session.verify_and_decrypt(encrypted)?;
        
        // Track received data for key rotation if enabled
        if self.session.should_rotate_keys() {
            self.session.track_received(encrypted.len());
        }
        
        Ok(result)
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Vec<u8> {
        self.session.close()
    }
    
    /// Stream data to the server lazily without materializing all chunks at once
    pub fn stream<'a>(&'a mut self, data: &'a [u8], chunk_size: Option<usize>) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        PqcSyncStreamSender::new(&mut self.session, Some(chunk_size)).stream_data(data)
    }

    /// Create a stream sender for efficiently streaming data
    pub fn stream_sender<'a>(&'a mut self, chunk_size: Option<usize>) -> PqcSyncStreamSender<'a> {
        PqcSyncStreamSender::new(&mut self.session, chunk_size)
    }

    /// Create a stream receiver to reassemble chunked data
    pub fn stream_receiver(&mut self, reassemble: bool) -> PqcSyncStreamReceiver<'_> {
        if reassemble {
            PqcSyncStreamReceiver::with_reassembly(&mut self.session)
        } else {
            PqcSyncStreamReceiver::new(&mut self.session)
        }
    }
    
    /// Check if key rotation is needed and initiate if necessary
    ///
    /// Returns a rotation message to send if rotation is needed,
    /// or None if no rotation is needed.
    pub fn check_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        if self.session.should_rotate_keys() {
            let rotation_msg = self.session.initiate_key_rotation()?;
            Ok(Some(rotation_msg))
        } else {
            Ok(None)
        }
    }
    
    /// Process a key rotation message from the server
    ///
    /// Returns a response message to send back to the server.
    pub fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        self.session.process_key_rotation(rotation_msg)
    }
    
    /// Complete key rotation based on the server's response
    pub fn complete_rotation(&mut self, response: &[u8]) -> Result<()> {
        self.session.complete_key_rotation(response)
    }
    
    /// Get the current connection state
    pub fn state(&self) -> SessionState {
        self.session.state()
    }
    
    /// Get a reference to the underlying session
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the underlying session
    pub fn session_mut(&mut self) -> &mut PqcSession {
        &mut self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_connect() -> Result<()> {
        let mut client = PqcClient::new()?;
        let pk = client.connect()?;
        
        // Just check that we got a public key of the right size
        assert_eq!(pk.len(), pqcrypto_kyber::kyber768::public_key_bytes());
        
        Ok(())
    }
}