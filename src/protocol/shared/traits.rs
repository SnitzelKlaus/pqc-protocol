/*!
Core traits for PQC protocol operations.

This module defines the traits that abstract over different implementation details
between sync and async APIs.
*/

use crate::core::error::Result;
use crate::core::session::SessionState;

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

/// Extension of PqcClientEndpoint for key rotation
pub trait PqcClientKeyRotation: PqcClientEndpoint + PqcKeyRotation {}

/// Extension of PqcServerEndpoint for key rotation
pub trait PqcServerKeyRotation: PqcServerEndpoint + PqcKeyRotation {}

/// Common trait for streaming capabilities
pub trait PqcStreaming {
    /// Get the current chunk size
    fn get_chunk_size(&self) -> usize;
    
    /// Set the chunk size
    fn set_chunk_size(&mut self, size: usize);
}