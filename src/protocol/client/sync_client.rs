/*!
Synchronous client implementation for the PQC protocol.
This client directly holds a PqcSession and uses the common module for shared operations.
*/

use crate::{
    core::{
        error::Result,
        session::{PqcSession, state::SessionState},
        constants::MAX_CHUNK_SIZE,
    },
    protocol::stream::sync_stream::{PqcSyncStreamSender, PqcSyncStreamReceiver},
};
use super::common;

/// Synchronous client for the PQC protocol.
pub struct PqcClient {
    session: PqcSession,
}

impl PqcClient {
    /// Create a new PQC client.
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(crate::core::session::state::Role::Client);
        Ok(Self { session })
    }
    
    /// Start the connection process.
    pub fn connect(&mut self) -> Result<Vec<u8>> {
        common::connect(&mut self.session)
    }
    
    /// Process the server's response to complete the connection.
    pub fn process_response(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        common::process_response(&mut self.session, ciphertext)
    }
    
    /// Complete authentication with the server's verification key.
    pub fn authenticate(&mut self, server_verification_key: &[u8]) -> Result<()> {
        common::authenticate(&mut self.session, server_verification_key)
    }
    
    /// Send a message to the server.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        common::send(&mut self.session, data)
    }
    
    /// Receive a message from the server.
    pub fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        common::receive(&mut self.session, encrypted)
    }
    
    /// Close the connection.
    pub fn close(&mut self) -> Vec<u8> {
        common::close(&mut self.session)
    }
    
    /// Lazily stream data to the server without materializing all chunks at once.
    pub fn stream<'a>(
        &'a mut self,
        data: &'a [u8],
        chunk_size: Option<usize>,
    ) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
        PqcSyncStreamSender::new(&mut self.session, Some(chunk_size)).stream_data(data)
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
    
    /// Check if key rotation is needed and initiate it if necessary.
    pub fn check_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        common::check_rotation(&mut self.session)
    }
    
    /// Process a key rotation message from the server.
    pub fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        common::process_rotation(&mut self.session, rotation_msg)
    }
    
    /// Complete key rotation based on the server's response.
    pub fn complete_rotation(&mut self, response: &[u8]) -> Result<()> {
        common::complete_rotation(&mut self.session, response)
    }
    
    /// Get the current connection state.
    pub fn state(&self) -> SessionState {
        self.session.state()
    }
    
    /// Get a reference to the underlying session.
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the underlying session.
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
        // Check that the public key has the expected size.
        assert_eq!(pk.len(), pqcrypto_kyber::kyber768::public_key_bytes());
        Ok(())
    }
}