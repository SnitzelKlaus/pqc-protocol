/*!
Asynchronous client implementation for the PQC protocol.

This module provides a full-featured async client implementation with support for 
configuration, key rotation, memory management, and streaming capabilities.
*/

use crate::core::{
    error::{Result, Error},
    session::{PqcSession, state::{Role, SessionState}},
    constants::MAX_CHUNK_SIZE,
    crypto::config::CryptoConfig,
};
use super::common;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::future::Future;
use uuid::Uuid;

use crate::protocol::stream::async_stream::{
    AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncStreamDataIterator,
};

/// Asynchronous client for the PQC protocol.
pub struct AsyncPqcClient {
    /// The shared session
    session: Arc<Mutex<PqcSession>>,
    
    /// Whether secure memory is enabled
    secure_memory_enabled: bool,
    
    /// Client identifier
    identifier: String,
}

impl AsyncPqcClient {
    /// Create a new async PQC client with default settings.
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Client);
        
        Ok(Self { 
            session: Arc::new(Mutex::new(session)),
            secure_memory_enabled: true,
            identifier: format!("AsyncPqcClient-{}", Uuid::new_v4()),
        })
    }

    /// Create a client with specific cryptographic configuration.
    pub async fn with_config(config: CryptoConfig) -> Result<Self> {
        let mut session = PqcSession::with_config(config)?;
        session.set_role(Role::Client);
        
        Ok(Self { 
            session: Arc::new(Mutex::new(session)),
            secure_memory_enabled: true,
            identifier: format!("AsyncPqcClient-{}", Uuid::new_v4()),
        })
    }
    
    /// Create a lightweight client for resource-constrained environments.
    pub async fn lightweight() -> Result<Self> {
        Self::with_config(CryptoConfig::lightweight()).await
    }
    
    /// Create a high-security client with stronger cryptographic settings.
    pub async fn high_security() -> Result<Self> {
        Self::with_config(CryptoConfig::high_security()).await
    }
    
    /// Create a hardware-optimized client that takes advantage of acceleration.
    pub async fn hardware_optimized() -> Result<Self> {
        Self::with_config(CryptoConfig::hardware_optimized()).await
    }
    
    /// Disable secure memory management.
    /// 
    /// This is useful for embedded platforms with limited resources.
    pub async fn disable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = false;
        Ok(())
    }
    
    /// Enable secure memory management.
    pub async fn enable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = true;
        Ok(())
    }
    
    /// Set a custom identifier for this client.
    pub async fn set_identifier(&mut self, identifier: String) {
        self.identifier = identifier;
    }
    
    /// Get the client's unique identifier.
    pub async fn get_identifier(&self) -> String {
        self.identifier.clone()
    }
    
    /// Get current protocol version.
    pub async fn protocol_version(&self) -> u8 {
        crate::core::constants::VERSION
    }

    /// Start the connection process with the server.
    /// 
    /// Returns the public key to be sent to the server.
    pub async fn connect(&self) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::connect(&mut session)
    }

    /// Process the server's response to the key exchange.
    /// 
    /// Takes the ciphertext from the server and returns the client's verification key.
    pub async fn process_response(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::process_response(&mut session, ciphertext)
    }

    /// Complete authentication with the server's verification key.
    pub async fn authenticate(&self, server_verification_key: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        common::authenticate(&mut session, server_verification_key)
    }

    /// Send data to the server.
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::send(&mut session, data)
    }

    /// Receive and decrypt data from the server.
    pub async fn receive(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::receive(&mut session, encrypted)
    }

    /// Close the connection with the server.
    pub async fn close(&self) -> Vec<u8> {
        let mut session = self.session.lock().unwrap();
        let close_msg = common::close(&mut session);
        
        // If secure memory is enabled, zero sensitive data when closing
        if self.secure_memory_enabled {
            self.zero_sensitive_memory().await;
        }
        
        close_msg
    }

    /// Create a stream sender to efficiently stream data to the server.
    pub fn stream_sender<'a, R: AsyncRead + Unpin + 'a>(
        &'a self,
        reader: &'a mut R,
        chunk_size: Option<usize>,
    ) -> AsyncPqcStreamSender<'a, R> {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        AsyncPqcStreamSender {
            reader,
            session: self.session.clone(),
            chunk_size,
        }
    }

    /// Stream data in chunks to the server.
    pub fn stream_data<'a>(
        &'a self,
        data: &'a [u8],
        chunk_size: Option<usize>,
    ) -> AsyncStreamDataIterator<'a> {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        AsyncStreamDataIterator {
            session: self.session.clone(),
            data,
            position: 0,
            chunk_size,
        }
    }

    /// Create a stream receiver to process data from the server.
    pub fn stream_receiver<'a, W: AsyncWrite + Unpin + 'a>(
        &'a self,
        writer: &'a mut W,
        reassemble: bool,
    ) -> AsyncPqcStreamReceiver<'a, W> {
        AsyncPqcStreamReceiver {
            writer,
            session: self.session.clone(),
            reassembly_buffer: if reassemble { Some(Vec::new()) } else { None },
        }
    }

    /// Check if key rotation is needed and initiate it if necessary.
    pub async fn check_rotation(&self) -> Result<Option<Vec<u8>>> {
        let mut session = self.session.lock().unwrap();
        common::check_rotation(&mut session)
    }

    /// Process a key rotation message from the server.
    pub async fn process_rotation(&self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::process_rotation(&mut session, rotation_msg)
    }

    /// Complete key rotation based on the server's response.
    pub async fn complete_rotation(&self, response: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        common::complete_rotation(&mut session, response)
    }

    /// Get the current connection state.
    pub async fn state(&self) -> Result<SessionState> {
        let session = self.session.lock().unwrap();
        Ok(session.state())
    }
    
    /// Get the current cryptographic configuration.
    pub async fn get_config(&self) -> Result<CryptoConfig> {
        let session = self.session.lock().unwrap();
        Ok(session.crypto_config().clone())
    }
    
    /// Update the cryptographic configuration.
    pub async fn update_config(&self, config: CryptoConfig) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        session.update_config(config)
    }
    
    /// Zero out sensitive memory.
    pub async fn zero_sensitive_memory(&self) {
        // In the async version, we can't replace the session directly
        // Instead, we'll try to reset it to a new state if possible
        if let Ok(mut session) = self.session.lock() {
            if let Ok(new_session) = PqcSession::new() {
                // Replace the session contents
                *session = new_session;
                // Set the role to client
                session.set_role(Role::Client);
            }
        }
    }
    
    /// Check if memory security is enabled.
    pub async fn is_memory_secure(&self) -> bool {
        self.secure_memory_enabled
    }
    
    /// Execute a function that requires mutable access to the session.
    pub async fn with_session<F, Fut, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PqcSession) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        let mut session = self.session.lock().unwrap();
        let future = f(&mut session);
        // Drop the lock before awaiting to avoid deadlocks
        drop(session);
        future.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::server::async_server::AsyncPqcServer;
    
    #[tokio::test]
    async fn test_client_init() -> Result<()> {
        let client = AsyncPqcClient::new().await?;
        let pk = client.connect().await?;
        // Check that the public key has the expected size.
        assert_eq!(pk.len(), pqcrypto_kyber::kyber768::public_key_bytes());
        Ok(())
    }
    
    #[tokio::test]
    async fn test_client_with_config() -> Result<()> {
        let config = CryptoConfig::high_security();
        let client = AsyncPqcClient::with_config(config.clone()).await?;
        
        let retrieved_config = client.get_config().await?;
        assert_eq!(retrieved_config.key_exchange, config.key_exchange);
        assert_eq!(retrieved_config.signature, config.signature);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_memory_security() -> Result<()> {
        let mut client = AsyncPqcClient::new().await?;
        
        assert!(client.is_memory_secure().await);
        client.disable_secure_memory().await?;
        assert!(!client.is_memory_secure().await);
        client.enable_secure_memory().await?;
        assert!(client.is_memory_secure().await);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let client = AsyncPqcClient::new().await?;
        let server = AsyncPqcServer::new().await?;
        
        // Client connects and gets public key
        let client_pk = client.connect().await?;
        
        // Server accepts connection and gets ciphertext and verification key
        let (server_ct, server_vk) = server.accept(&client_pk).await?;
        
        // Client processes server response and gets its own verification key
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