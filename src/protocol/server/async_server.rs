/*!
Asynchronous server implementation for the PQC protocol.

This module provides a full-featured async server implementation with support for 
configuration, key rotation, memory management, and streaming capabilities.
*/

use crate::core::{
    error::{Result, Error},
    session::{PqcSession, state::{Role, SessionState}},
    constants::MAX_CHUNK_SIZE,
    crypto::config::CryptoConfig,
    memory::{SecureMemory, Zeroize, SecureVec, SecureSession},
};
use super::common;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::future::Future;
use uuid::Uuid;

use crate::protocol::stream::async_stream::{
    AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncStreamDataIterator,
};

/// Asynchronous server for the PQC protocol.
pub struct AsyncPqcServer {
    /// The shared session
    session: Arc<Mutex<PqcSession>>,
    
    /// Whether secure memory is enabled
    secure_memory_enabled: bool,
    
    /// Server identifier
    identifier: String,
}

impl AsyncPqcServer {
    /// Create a new async PQC server with default settings.
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        
        Ok(Self { 
            session: Arc::new(Mutex::new(session)),
            secure_memory_enabled: true,
            identifier: format!("AsyncPqcServer-{}", Uuid::new_v4()),
        })
    }

    /// Create a server with specific cryptographic configuration.
    pub async fn with_config(config: CryptoConfig) -> Result<Self> {
        let mut session = PqcSession::with_config(config)?;
        session.set_role(Role::Server);
        
        Ok(Self { 
            session: Arc::new(Mutex::new(session)),
            secure_memory_enabled: true,
            identifier: format!("AsyncPqcServer-{}", Uuid::new_v4()),
        })
    }
    
    /// Create a lightweight server for resource-constrained environments.
    pub async fn lightweight() -> Result<Self> {
        let server = Self::with_config(CryptoConfig::lightweight()).await?;
        
        // Apply lightweight memory settings
        server.with_session(|session| async move {
            session.disable_secure_memory();
            Ok(())
        }).await?;
        
        Ok(server)
    }
    
    /// Create a high-security server with stronger cryptographic settings.
    pub async fn high_security() -> Result<Self> {
        let server = Self::with_config(CryptoConfig::high_security()).await?;
        
        // Apply high security memory settings
        server.with_session(|session| async move {
            session.set_memory_security_level(crate::core::memory::MemorySecurity::Maximum);
            session.enable_secure_memory();
            Ok(())
        }).await?;
        
        Ok(server)
    }
    
    /// Create a hardware-optimized server that takes advantage of acceleration.
    pub async fn hardware_optimized() -> Result<Self> {
        Self::with_config(CryptoConfig::hardware_optimized()).await
    }
    
    /// Disable secure memory management.
    /// 
    /// This is useful for embedded platforms with limited resources.
    pub async fn disable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = false;
        
        self.with_session(|session| async move {
            session.disable_secure_memory();
            Ok(())
        }).await?;
        
        Ok(())
    }
    
    /// Enable secure memory management.
    pub async fn enable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = true;
        
        self.with_session(|session| async move {
            session.enable_secure_memory();
            Ok(())
        }).await?;
        
        Ok(())
    }
    
    /// Set a custom identifier for this server.
    pub async fn set_identifier(&mut self, identifier: String) {
        self.identifier = identifier;
    }
    
    /// Get the server's unique identifier.
    pub async fn get_identifier(&self) -> String {
        self.identifier.clone()
    }
    
    /// Get current protocol version.
    pub async fn protocol_version(&self) -> u8 {
        crate::core::constants::VERSION
    }

    /// Accept a connection from a client.
    /// 
    /// Takes the client's public key and returns the ciphertext and server's verification key.
    pub async fn accept(&self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut session = self.session.lock().unwrap();
        common::accept(&mut session, client_public_key)
    }

    /// Complete authentication with the client's verification key.
    pub async fn authenticate(&self, client_verification_key: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        common::authenticate(&mut session, client_verification_key)
    }

    /// Send data to the client.
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::send(&mut session, data)
    }

    /// Receive and decrypt data from the client.
    pub async fn receive(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::receive(&mut session, encrypted)
    }

    /// Close the connection with the client.
    pub async fn close(&self) -> Vec<u8> {
        let mut session = self.session.lock().unwrap();
        let close_msg = common::close(&mut session);
        
        // If secure memory is enabled, zero sensitive data when closing
        if self.secure_memory_enabled {
            self.zero_sensitive_memory().await;
        }
        
        close_msg
    }

    /// Create a stream sender to efficiently stream data to the client.
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

    /// Stream data in chunks to the client.
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

    /// Create a stream receiver to process data from the client.
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

    /// Process a key rotation message from the client.
    pub async fn process_rotation(&self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::process_rotation(&mut session, rotation_msg)
    }

    /// Complete key rotation based on the client's response.
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
            // Call the secure session's erase method
            session.erase_sensitive_memory();
            
            // Optionally replace with a new session
            if let Ok(new_session) = PqcSession::new() {
                // Replace the session contents
                *session = new_session;
                // Set the role to server
                session.set_role(Role::Server);
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

// Implement Zeroize trait for AsyncPqcServer
impl Zeroize for AsyncPqcServer {
    fn zeroize(&mut self) {
        // Use internal zeroization for async context
        if let Ok(mut session) = self.session.lock() {
            session.erase_sensitive_memory();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::client::async_client::AsyncPqcClient;
    
    #[tokio::test]
    async fn test_server_init() -> Result<()> {
        let server = AsyncPqcServer::new().await?;
        assert_eq!(server.state().await?.to_string(), "New");
        Ok(())
    }
    
    #[tokio::test]
    async fn test_server_with_config() -> Result<()> {
        let config = CryptoConfig::high_security();
        let server = AsyncPqcServer::with_config(config.clone()).await?;
        
        let retrieved_config = server.get_config().await?;
        assert_eq!(retrieved_config.key_exchange, config.key_exchange);
        assert_eq!(retrieved_config.signature, config.signature);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_memory_security() -> Result<()> {
        let mut server = AsyncPqcServer::new().await?;
        
        assert!(server.is_memory_secure().await);
        server.disable_secure_memory().await?;
        assert!(!server.is_memory_secure().await);
        server.enable_secure_memory().await?;
        assert!(server.is_memory_secure().await);
        
        // Test that the disable/enable actually affects the underlying session
        server.with_session(|session| async move {
            #[cfg(feature = "memory-lock")]
            assert!(session.memory_manager().is_memory_locking_enabled());
            Ok(())
        }).await?;
        
        server.disable_secure_memory().await?;
        
        server.with_session(|session| async move {
            #[cfg(feature = "memory-lock")]
            assert!(!session.memory_manager().is_memory_locking_enabled());
            Ok(())
        }).await?;
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_client_server_handshake() -> Result<()> {
        // Create client and server
        let client = AsyncPqcClient::new().await?;
        let server = AsyncPqcServer::new().await?;
        
        // Client initiates key exchange
        let client_pk = client.connect().await?;
        
        // Server accepts the key exchange
        let (server_ct, server_vk) = server.accept(&client_pk).await?;
        
        // Client processes server's response
        let client_vk = client.process_response(&server_ct).await?;
        
        // Complete authentication
        server.authenticate(&client_vk).await?;
        client.authenticate(&server_vk).await?;
        
        // Verify both are in established state
        assert_eq!(client.state().await?.to_string(), "Established");
        assert_eq!(server.state().await?.to_string(), "Established");
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_key_rotation() -> Result<()> {
        // Setup client and server
        let client = AsyncPqcClient::new().await?;
        let server = AsyncPqcServer::new().await?;
        
        // Complete handshake (simplified for test)
        let client_pk = client.connect().await?;
        let (server_ct, server_vk) = server.accept(&client_pk).await?;
        let client_vk = client.process_response(&server_ct).await?;
        server.authenticate(&client_vk).await?;
        client.authenticate(&server_vk).await?;
        
        // Test key rotation - this is a simplified version
        // In production, this would be triggered by session statistics
        if let Some(rotation_msg) = client.check_rotation().await? {
            let response = server.process_rotation(&rotation_msg).await?;
            client.complete_rotation(&response).await?;
            
            // Test data exchange after rotation
            let test_data = b"Data after rotation";
            let encrypted = client.send(test_data).await?;
            let decrypted = server.receive(&encrypted).await?;
            assert_eq!(test_data, &decrypted[..]);
        }
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_zeroize() -> Result<()> {
        let mut server = AsyncPqcServer::new().await?;
        
        // Create a client and start handshake to set up some state
        let client = AsyncPqcClient::new().await?;
        let client_pk = client.connect().await?;
        let _ = server.accept(&client_pk).await?;
        
        // Test zeroize implementation
        server.zeroize();
        
        // Session should still be in a consistent state
        assert_eq!(server.state().await?, SessionState::KeyExchangeCompleted);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_zero_sensitive_memory() -> Result<()> {
        let server = AsyncPqcServer::new().await?;
        
        // Create a client and start handshake to set up some state
        let client = AsyncPqcClient::new().await?;
        let client_pk = client.connect().await?;
        let _ = server.accept(&client_pk).await?;
        
        // Test manual memory zeroing
        server.zero_sensitive_memory().await;
        
        // Session should be reset to a new state
        assert_eq!(server.state().await?, SessionState::New);
        
        Ok(())
    }
}