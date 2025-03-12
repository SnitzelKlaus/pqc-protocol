/*!
Synchronous server implementation for the PQC protocol.
This server supports the new unified API.
*/

use crate::{
    core::{
        error::Result,
        session::{PqcSession, state::{SessionState, Role}},
        constants::MAX_CHUNK_SIZE,
        crypto::config::{CryptoConfig, KeyExchangeAlgorithm},
        memory::SecureMemory,
    },
    protocol::{
        stream::sync_stream::{PqcSyncStreamSender, PqcSyncStreamReceiver},
        shared::traits::{
            PqcEndpoint, PqcServerEndpoint, PqcKeyRotation, 
            PqcStreamSender, PqcStreamReceiver, 
            PqcConfigurable, PqcMemoryControl, UnifiedPqcServer
        },
    },
};
use super::common;

/// Synchronous server for the PQC protocol.
pub struct PqcServer {
    /// The underlying session
    session: PqcSession,
    
    /// Whether secure memory is enabled
    secure_memory_enabled: bool,
    
    /// Server identifier
    identifier: String,
}

impl PqcServer {
    /// Create a new PQC server.
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        
        Ok(Self { 
            session,
            secure_memory_enabled: true,
            identifier: format!("PqcServer-{}", uuid::Uuid::new_v4()),
        })
    }
    
    /// Create a server with specific configuration.
    pub fn with_config(config: CryptoConfig) -> Result<Self> {
        let mut session = PqcSession::with_config(config)?;
        session.set_role(Role::Server);
        
        Ok(Self { 
            session,
            secure_memory_enabled: true,
            identifier: format!("PqcServer-{}", uuid::Uuid::new_v4()),
        })
    }
    
    /// Set role (should always be Server for this implementation)
    pub fn set_role(&mut self, role: Role) {
        assert_eq!(role, Role::Server, "PqcServer should only be used with Server role");
        self.session.set_role(role);
    }
    
    /// Get the current role
    pub fn role(&self) -> Role {
        Role::Server
    }
    
    /// Disable secure memory management.
    /// 
    /// This is useful for embedded platforms with limited resources.
    pub fn disable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = false;
        Ok(())
    }
    
    /// Enable secure memory management.
    pub fn enable_secure_memory(&mut self) -> Result<()> {
        self.secure_memory_enabled = true;
        Ok(())
    }
    
    /// Set a custom identifier for this server.
    pub fn set_identifier(&mut self, identifier: String) {
        self.identifier = identifier;
    }
    
    /// Get a reference to the underlying session
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the underlying session
    pub fn session_mut(&mut self) -> &mut PqcSession {
        &mut self.session
    }
    
    /// Get the current state directly
    pub fn state(&self) -> SessionState {
        self.session.state()
    }
    
    /// Stream data in chunks with the specified size
    pub fn stream<'a>(
        &'a mut self,
        data: &'a [u8],
        chunk_size: Option<usize>,
    ) -> Result<Vec<Result<Vec<u8>>>> {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        let mut sender = PqcSyncStreamSender::new(&mut self.session, Some(chunk_size));
        let chunks: Vec<Result<Vec<u8>>> = sender.stream_data(data).collect();
        Ok(chunks)
    }
    
    /// Create a stream sender for efficiently streaming data.
    pub fn stream_sender<'a>(&'a mut self, chunk_size: Option<usize>) -> PqcSyncStreamSender<'a> {
        PqcSyncStreamSender::new(&mut self.session, chunk_size)
    }
    
    /// Create a stream receiver to reassemble chunked data.
    pub fn stream_receiver(&mut self, reassemble: bool) -> PqcSyncStreamReceiver<'_> {
        if reassemble {
            PqcSyncStreamReceiver::with_reassembly(&mut self.session)
        } else {
            PqcSyncStreamReceiver::new(&mut self.session)
        }
    }
}

// Implement the PqcEndpoint trait

impl PqcEndpoint for PqcServer {
    fn get_state(&self) -> Result<SessionState> {
        Ok(self.session.state())
    }
    
    fn close(&mut self) -> Vec<u8> {
        let close_msg = common::close(&mut self.session);
        
        // If secure memory is enabled, zero sensitive data when closing
        if self.secure_memory_enabled {
            self.zero_sensitive_memory();
        }
        
        close_msg
    }
}

// Implement the PqcServerEndpoint trait

impl PqcServerEndpoint for PqcServer {
    fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        common::accept(&mut self.session, client_public_key)
    }
    
    fn authenticate(&mut self, client_verification_key: &[u8]) -> Result<()> {
        common::authenticate(&mut self.session, client_verification_key)
    }
    
    fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        common::send(&mut self.session, data)
    }
    
    fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        common::receive(&mut self.session, encrypted)
    }
}

// Implement the PqcKeyRotation trait

impl PqcKeyRotation for PqcServer {
    fn check_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        common::check_rotation(&mut self.session)
    }
    
    fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        common::process_rotation(&mut self.session, rotation_msg)
    }
    
    fn complete_rotation(&mut self, response: &[u8]) -> Result<()> {
        common::complete_rotation(&mut self.session, response)
    }
}

// Implement the PqcConfigurable trait

impl PqcConfigurable for PqcServer {
    fn get_config(&self) -> &CryptoConfig {
        self.session.crypto_config()
    }
    
    fn update_config(&mut self, config: CryptoConfig) -> Result<()> {
        self.session.update_config(config)
    }
}

// Implement the PqcMemoryControl trait

impl PqcMemoryControl for PqcServer {
    fn zero_sensitive_memory(&mut self) {
        // Ideally, we would directly call into the session's secure memory
        // For now, we just reset the session to clear sensitive data
        if let Ok(new_session) = PqcSession::new() {
            self.session = new_session;
            self.session.set_role(Role::Server);
        }
    }
    
    fn is_memory_secure(&self) -> bool {
        self.secure_memory_enabled
    }
    
    fn set_memory_security(&mut self, secure: bool) -> Result<()> {
        if secure {
            self.enable_secure_memory()
        } else {
            self.disable_secure_memory()
        }
    }
}

// Implement the UnifiedPqcEndpoint trait

impl UnifiedPqcServer for PqcServer {
    fn identifier(&self) -> String {
        self.identifier.clone()
    }
    
    fn protocol_version(&self) -> u8 {
        crate::core::constants::VERSION
    }
    
    fn create_stream_sender<'a>(&'a mut self) -> Box<dyn PqcStreamSender + 'a> {
        // Create a wrapper object to adapt PqcSyncStreamSender to the unified PqcStreamSender trait
        struct SenderWrapper<'a> {
            inner: PqcSyncStreamSender<'a>,
        }
        
        impl<'a> PqcStreamSender for SenderWrapper<'a> {
            fn chunk_size(&self) -> usize {
                self.inner.chunk_size()
            }
            
            fn set_chunk_size(&mut self, size: usize) {
                self.inner.set_chunk_size(size);
            }
            
            fn stream_data<'b>(&'b mut self, data: &'b [u8]) -> Box<dyn Iterator<Item = Result<Vec<u8>>> + 'b> {
                Box::new(self.inner.stream_data(data))
            }
        }
        
        Box::new(SenderWrapper {
            inner: PqcSyncStreamSender::new(&mut self.session, Some(MAX_CHUNK_SIZE)),
        })
    }
    
    fn create_stream_receiver<'a>(&'a mut self, reassemble: bool) -> Box<dyn PqcStreamReceiver + 'a> {
        // Create a wrapper object to adapt PqcSyncStreamReceiver to the unified PqcStreamReceiver trait
        struct ReceiverWrapper<'a> {
            inner: PqcSyncStreamReceiver<'a>,
        }
        
        impl<'a> PqcStreamReceiver for ReceiverWrapper<'a> {
            fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
                self.inner.process_chunk(chunk)
            }
            
            fn enable_reassembly(&mut self) {
                self.inner.enable_reassembly();
            }
            
            fn disable_reassembly(&mut self) {
                self.inner.disable_reassembly();
            }
            
            fn reassembled_data(&self) -> Option<&[u8]> {
                self.inner.reassembled_data()
            }
            
            fn take_reassembled_data(&mut self) -> Option<Vec<u8>> {
                self.inner.take_reassembled_data()
            }
        }
        
        let receiver = if reassemble {
            PqcSyncStreamReceiver::with_reassembly(&mut self.session)
        } else {
            PqcSyncStreamReceiver::new(&mut self.session)
        };
        
        Box::new(ReceiverWrapper {
            inner: receiver,
        })
    }
}

// Implement no_std compatible features for embedded systems
#[cfg(not(feature = "std"))]
impl PqcServer {
    /// Create a server optimized for embedded systems
    pub fn embedded() -> Result<Self> {
        let config = CryptoConfig::lightweight();
        let mut server = Self::with_config(config)?;
        server.disable_secure_memory()?;
        Ok(server)
    }
    
    /// Get the estimated memory usage of this server
    pub fn memory_usage(&self) -> usize {
        // This is a rough estimate - would need to be calculated more precisely
        // based on the actual algorithms in use
        let base_size = 8192; // Base session size
        
        // Add algorithm-specific sizes
        let algo_size = match self.session.crypto_config().key_exchange {
            KeyExchangeAlgorithm::Kyber512 => 2048,
            KeyExchangeAlgorithm::Kyber768 => 3072,
            KeyExchangeAlgorithm::Kyber1024 => 4096,
        };
        
        base_size + algo_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let mut client = crate::protocol::client::sync_client::PqcClient::new()?;
        let mut server = PqcServer::new()?;
        
        // Client connects and gets public key
        let client_pk = client.connect()?;
        
        // Server accepts connection and gets ciphertext and verification key
        let (server_ct, server_vk) = server.accept(&client_pk)?;
        
        // Client processes server response and gets its own verification key
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
    
    #[test]
    fn test_unified_traits() -> Result<()> {
        let mut server = PqcServer::new()?;
        
        // Test PqcConfigurable
        assert_eq!(server.get_config().key_exchange, KeyExchangeAlgorithm::Kyber768);
        
        // Test UnifiedPqcEndpoint
        assert!(!server.identifier().is_empty());
        assert_eq!(server.protocol_version(), crate::core::constants::VERSION);
        
        // Test PqcMemoryControl
        assert!(server.is_memory_secure());
        server.disable_secure_memory()?;
        assert!(!server.is_memory_secure());
        server.enable_secure_memory()?;
        assert!(server.is_memory_secure());
        
        Ok(())
    }
}