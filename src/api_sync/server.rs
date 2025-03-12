/*!
Synchronous server implementation for the PQC protocol.

This module provides the server-side operations for the synchronous API.
*/

use crate::{
    error::{Result, Error},
    session::{PqcSession, Role, SessionState},
    security::rotation::PqcSessionKeyRotation,
    constants::MAX_CHUNK_SIZE,
};

// Required traits for from_bytes/as_bytes methods
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, Ciphertext as KemCiphertext};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;

use super::stream::{PqcSyncStreamSender, PqcSyncStreamReceiver};

/// Server-side operations for the PQC protocol
pub struct PqcServer {
    /// The underlying session
    session: PqcSession,
}

impl PqcServer {
    /// Create a new PQC server
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        Ok(Self { session })
    }
    
    /// Accept a connection from a client
    ///
    /// Takes the client's public key and returns the ciphertext and verification key to send back.
    pub fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Convert bytes to Kyber public key
        let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(client_public_key)
            .map_err(|_| {
                crate::key_exchange_err!(crate::error::KeyExchangeError::InvalidPublicKey)
            })?;
        
        // Accept the key exchange
        let ciphertext = self.session.accept_key_exchange(&pk)?;
        
        // Return the ciphertext and verification key
        Ok((
            ciphertext.as_bytes().to_vec(),
            self.session.local_verification_key().as_bytes().to_vec()
        ))
    }
    
    /// Complete authentication with the client's verification key
    ///
    /// Takes the client's verification key and completes the connection.
    pub fn authenticate(&mut self, client_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(client_verification_key)
            .map_err(|_| {
                crate::auth_err!(crate::error::AuthError::InvalidKeyFormat)
            })?;
        
        // Set the remote verification key
        self.session.set_remote_verification_key(vk)?;
        
        // Complete authentication
        self.session.complete_authentication()?;
        
        Ok(())
    }
    
    /// Send a message to the client
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let result = self.session.encrypt_and_sign(data)?;
        
        // Track sent data for key rotation if enabled
        if self.session.should_rotate_keys() {
            self.session.track_sent(result.len());
        }
        
        Ok(result)
    }
    
    /// Receive a message from the client
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
    
    /// Stream data to the client lazily
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
    
    /// Process a key rotation message from the client
    ///
    /// Returns a response message to send back to the client.
    pub fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        self.session.process_key_rotation(rotation_msg)
    }
    
    /// Complete key rotation based on the client's response
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
    fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let mut client = crate::api_sync::PqcClient::new()?;
        let mut server = PqcServer::new()?;
        
        // Client connects and gets public key
        let client_pk = client.connect()?;
        
        // Server accepts connection and gets ciphertext and verification key
        let (server_ct, server_vk) = server.accept(&client_pk)?;
        
        // Client processes server response and gets own verification key
        let client_vk = client.process_response(&server_ct)?;
        
        // Server authenticates with client verification key
        server.authenticate(&client_vk)?;
        
        // Client authenticates with server verification key
        client.authenticate(&server_vk)?;
        
        // Test data exchange
        let test_message = b"Hello from the client!";
        let encrypted = client.send(test_message)?;
        let decrypted = server.receive(&encrypted)?;
        
        assert_eq!(test_message, &decrypted[..]);
        
        // Test in the other direction
        let response_message = b"Hello from the server!";
        let encrypted = server.send(response_message)?;
        let decrypted = client.receive(&encrypted)?;
        
        assert_eq!(response_message, &decrypted[..]);
        
        Ok(())
    }
}