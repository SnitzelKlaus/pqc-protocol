/*!
Core traits for PQC protocol operations.

This module defines the traits that abstract over different implementation details
between sync and async APIs.
*/

use crate::core::error::Result;
use crate::core::session::SessionState;
use crate::core::crypto::config::CryptoConfig;

/// Common trait for both sync and async protocol implementations
pub trait PqcEndpoint {
    /// Get the current connection state
    fn get_state(&self) -> Result<SessionState>;
    
    /// Close the connection
    fn close(&mut self) -> Vec<u8>;
}

/// Common trait for client-side protocol implementations
pub trait PqcClientEndpoint: PqcEndpoint {
    /// Connect to a server and return public key
    fn connect(&mut self) -> Result<Vec<u8>>;
    
    /// Process server response and return client verification key
    fn process_response(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Complete authentication with server's verification key
    fn authenticate(&mut self, server_verification_key: &[u8]) -> Result<()>;
    
    /// Send data to the server
    fn send(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Receive data from the server
    fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>>;
}

/// Common trait for server-side protocol implementations
pub trait PqcServerEndpoint: PqcEndpoint {
    /// Accept a connection from a client
    fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Complete authentication with client's verification key
    fn authenticate(&mut self, client_verification_key: &[u8]) -> Result<()>;
    
    /// Send data to the client
    fn send(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Receive data from the client
    fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>>;
}

/// Common trait for key rotation operations
pub trait PqcKeyRotation {
    /// Check if key rotation is needed
    fn check_rotation(&mut self) -> Result<Option<Vec<u8>>>;
    
    /// Process a key rotation message
    fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>>;
    
    /// Complete key rotation based on response
    fn complete_rotation(&mut self, response: &[u8]) -> Result<()>;
}

/// Trait for streaming data in chunks
pub trait PqcStreamSender {
    /// Get the current chunk size
    fn chunk_size(&self) -> usize;
    
    /// Set a new chunk size
    fn set_chunk_size(&mut self, size: usize);
    
    /// Stream data from a buffer
    fn stream_data<'a>(&'a mut self, data: &'a [u8]) -> Box<dyn Iterator<Item = Result<Vec<u8>>> + 'a>;
}

/// Trait for reassembling streamed data
pub trait PqcStreamReceiver {
    /// Process a received encrypted chunk
    fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>>;
    
    /// Enable chunk reassembly
    fn enable_reassembly(&mut self);
    
    /// Disable chunk reassembly
    fn disable_reassembly(&mut self);
    
    /// Get the reassembled data if available
    fn reassembled_data(&self) -> Option<&[u8]>;
    
    /// Take ownership of the reassembled data
    fn take_reassembled_data(&mut self) -> Option<Vec<u8>>;
}

/// Trait for endpoints that can be configured
pub trait PqcConfigurable {
    /// Get the current configuration
    fn get_config(&self) -> &CryptoConfig;
    
    /// Update the configuration
    fn update_config(&mut self, config: CryptoConfig) -> Result<()>;
}

/// Trait for endpoints that support memory management
pub trait PqcMemoryControl {
    /// Zero sensitive memory
    fn zero_sensitive_memory(&mut self);
    
    /// Check if memory is securely managed
    fn is_memory_secure(&self) -> bool;
    
    /// Set memory security level
    fn set_memory_security(&mut self, secure: bool) -> Result<()>;
}

/// Client with key rotation capabilities
pub trait PqcClientKeyRotation: PqcClientEndpoint + PqcKeyRotation {}

/// Server with key rotation capabilities  
pub trait PqcServerKeyRotation: PqcServerEndpoint + PqcKeyRotation {}

/// Common trait for streaming capabilities
pub trait PqcStreaming {
    /// Get the current chunk size
    fn get_chunk_size(&self) -> usize;
    
    /// Set the chunk size
    fn set_chunk_size(&mut self, size: usize);
}

/// Unified trait for endpoints with all features
pub trait UnifiedPqcEndpoint: PqcEndpoint + PqcKeyRotation + PqcConfigurable + PqcMemoryControl {
    /// Get a string identifier for this endpoint
    fn identifier(&self) -> String;
    
    /// Get the protocol version
    fn protocol_version(&self) -> u8;
}

/// Unified trait for client with all features
pub trait UnifiedPqcClient: UnifiedPqcEndpoint + PqcClientEndpoint {
    /// Create a stream sender
    fn create_stream_sender<'a>(&'a mut self) -> Box<dyn PqcStreamSender + 'a>;
    
    /// Create a stream receiver
    fn create_stream_receiver<'a>(&'a mut self, reassemble: bool) -> Box<dyn PqcStreamReceiver + 'a>;
}

/// Unified trait for server with all features
pub trait UnifiedPqcServer: UnifiedPqcEndpoint + PqcServerEndpoint {
    /// Create a stream sender
    fn create_stream_sender<'a>(&'a mut self) -> Box<dyn PqcStreamSender + 'a>;
    
    /// Create a stream receiver
    fn create_stream_receiver<'a>(&'a mut self, reassemble: bool) -> Box<dyn PqcStreamReceiver + 'a>;
}