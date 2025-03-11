/*!
Asynchronous server implementation for the PQC protocol.

This module provides the server-side operations for the asynchronous API.
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

/// Asynchronous server for the PQC protocol
pub struct AsyncPqcServer {
    /// The underlying session
    session: Arc<Mutex<PqcSession>>,
}

impl AsyncPqcServer {
    /// Create a new async PQC server
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        Ok(Self { 
            session: Arc::new(Mutex::new(session))
        })
    }
    
    /// Accept a connection asynchronously
    ///
    /// Takes the client's public key and returns the ciphertext and verification key to send back.
    pub async fn accept(&self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Convert bytes to Kyber public key
        let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(client_public_key)
            .map_err(|_| {
                crate::key_exchange_err!(crate::error::KeyExchangeError::InvalidPublicKey)
            })?;
        
        let mut session = self.session.lock().unwrap();
        
        // Accept the key exchange
        let ciphertext = session.accept_key_exchange(&pk)?;
        
        // Return the ciphertext and verification key
        Ok((
            ciphertext.as_bytes().to_vec(),
            session.local_verification_key().as_bytes().to_vec()
        ))
    }
    
    /// Complete authentication asynchronously with the client's verification key
    ///
    /// Takes the client's verification key and completes the connection.
    pub async fn authenticate(&self, client_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(client_verification_key)
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
    
    /// Send a message to the client asynchronously
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        let result = session.encrypt_and_sign(data)?;
        
        // Track sent data for key rotation if enabled
        if session.should_rotate_keys() {
            session.track_sent(result.len());
        }
        
        Ok(result)
    }
    
    /// Receive a message from the client asynchronously
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
    
    /// Create a stream sender to stream data to the client
    pub fn stream_sender<'a, R: AsyncRead + Unpin + 'a>(
        &'a self,
        reader: &'a mut R,
        chunk_size: Option<usize>,
    ) -> AsyncPqcSendStream<'a, R> {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        AsyncPqcSendStream::new(reader, self.session.clone(), chunk_size)
    }
    
    /// Create a stream receiver to process data from the client
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
    
    /// Process a key rotation message from the client
    ///
    /// Returns a response message to send back to the client.
    pub async fn process_rotation(&self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        session.process_key_rotation(rotation_msg)
    }
    
    /// Complete key rotation based on the client's response
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
    use crate::async::AsyncPqcClient;
    
    #[tokio::test]
    async fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let client = AsyncPqcClient::new().await?;
        let server = AsyncPqcServer::new().await?;
        
        // Client connects and gets public key
        let client_pk = client.connect().await?;
        
        // Server accepts connection and gets ciphertext and verification key
        let (server_ct, server_vk) = server.accept(&client_pk).await?;
        
        // Client processes server response and gets own verification key
        let client_vk = client.process_response(&server_ct).await?;
        
        // Server authenticates with client verification key
        server.authenticate(&client_vk).await?;
        
        // Client authenticates with server verification key
        client.authenticate(&server_vk).await?;
        
        // Test data exchange
        let test_message = b"Hello from the client!";
        let encrypted = client.send(test_message).await?;
        let decrypted = server.receive(&encrypted).await?;
        
        assert_eq!(test_message, &decrypted[..]);
        
        // Test in the other direction
        let response_message = b"Hello from the server!";
        let encrypted = server.send(response_message).await?;
        let decrypted = client.receive(&encrypted).await?;
        
        assert_eq!(response_message, &decrypted[..]);
        
        Ok(())
    }
}