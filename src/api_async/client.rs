/*!
Asynchronous client implementation for the PQC protocol.

This module provides the client-side operations for the asynchronous API.
*/

use crate::{
    error::{Result, Error},
    session::{PqcSession, Role, SessionState},
    security::rotation::PqcSessionKeyRotation,
    constants::MAX_CHUNK_SIZE,
};

use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::future::Future;
use std::pin::Pin;

use super::stream::{AsyncPqcSendStream, AsyncPqcReceiveStream};

/// Asynchronous client for the PQC protocol
pub struct AsyncPqcClient {
    /// The underlying session
    session: Arc<Mutex<PqcSession>>,
}

impl AsyncPqcClient {
    /// Create a new async PQC client
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Client);
        Ok(Self { 
            session: Arc::new(Mutex::new(session))
        })
    }
    
    /// Start the connection process asynchronously
    ///
    /// Initiates key exchange and returns the public key to send to the server.
    pub async fn connect(&self) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        let public_key = session.init_key_exchange()?;
        Ok(public_key.as_bytes().to_vec())
    }
    
    /// Process the server's response asynchronously
    ///
    /// Takes the ciphertext from the server and returns the verification key to send.
    pub async fn process_response(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Convert bytes to Kyber ciphertext
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| {
                crate::crypto_err!(crate::error::CryptoError::InvalidKeyFormat)
            })?;
        
        let mut session = self.session.lock().unwrap();
        
        // Process the ciphertext
        session.process_key_exchange(&ct)?;
        
        // Return the verification key
        Ok(session.local_verification_key().as_bytes().to_vec())
    }
    
    /// Complete authentication asynchronously with the server's verification key
    ///
    /// Takes the server's verification key and completes the connection.
    pub async fn authenticate(&self, server_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(server_verification_key)
            .map_err(|_| {
                crate::auth_err!(crate::error::AuthError::InvalidKeyFormat)
            })?;
        
        let mut session = self.session.lock().unwrap();
        
        // Set the remote verification key
        session.set_remote_verification_key(vk)?;
        
        // Complete authentication
        session.complete_authentication()?;
        
        Ok(())
    }
    
    /// Send a message to the server asynchronously
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        let result = session.encrypt_and_sign(data)?;
        
        // Track sent data for key rotation if enabled
        if session.should_rotate_keys() {
            session.track_sent(result.len());
        }
        
        Ok(result)
    }
    
    /// Receive a message from the server asynchronously
    pub async fn receive(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        let result = session.verify_and_decrypt(encrypted)?;
        
        // Track received data for key rotation if enabled
        if session.should_rotate_keys() {
            session.track_received(encrypted.len());
        }
        
        Ok(result)
    }
    
    /// Close the connection asynchronously
    pub async fn close(&self) -> Vec<u8> {
        let mut session = self.session.lock().unwrap();
        session.close()
    }
    
    /// Create a stream sender to stream data to the server
    pub fn stream_sender<'a, R: AsyncRead + Unpin + 'a>(
        &'a self,
        reader: &'a mut R,
        chunk_size: Option<usize>,
    ) -> AsyncPqcSendStream<'a, R> {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        AsyncPqcSendStream::new(reader, self.session.clone(), chunk_size)
    }
    
    /// Create a stream receiver to process data from the server
    pub fn stream_receiver<'a, W: AsyncWrite + Unpin + 'a>(
        &'a self,
        writer: &'a mut W,
        reassemble: bool,
    ) -> AsyncPqcReceiveStream<'a, W> {
        AsyncPqcReceiveStream::new(writer, self.session.clone(), reassemble)
    }
    
    /// Check if key rotation is needed and initiate if necessary
    ///
    /// Returns a rotation message to send if rotation is needed,
    /// or None if no rotation is needed.
    pub async fn check_rotation(&self) -> Result<Option<Vec<u8>>> {
        let mut session = self.session.lock().unwrap();
        if session.should_rotate_keys() {
            let rotation_msg = session.initiate_key_rotation()?;
            Ok(Some(rotation_msg))
        } else {
            Ok(None)
        }
    }
    
    /// Process a key rotation message from the server
    ///
    /// Returns a response message to send back to the server.
    pub async fn process_rotation(&self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        session.process_key_rotation(rotation_msg)
    }
    
    /// Complete key rotation based on the server's response
    pub async fn complete_rotation(&self, response: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        session.complete_key_rotation(response)
    }
    
    /// Get the current connection state
    pub fn state(&self) -> Result<SessionState> {
        let session = self.session.lock().unwrap();
        Ok(session.state())
    }
    
    /// Execute a function that requires mutable access to the session
    pub async fn with_session<F, Fut, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PqcSession) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        let mut session = self.session.lock().unwrap();
        let future = f(&mut session);
        // Need to drop the lock before awaiting to avoid deadlocks
        drop(session);
        future.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_client_init() -> Result<()> {
        let client = AsyncPqcClient::new().await?;
        let pk = client.connect().await?;
        
        // Just check that we got a public key of the right size
        assert_eq!(pk.len(), pqcrypto_kyber::kyber768::public_key_bytes());
        
        Ok(())
    }
}