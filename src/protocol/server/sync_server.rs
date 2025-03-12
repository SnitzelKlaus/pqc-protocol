/*!
Synchronous server implementation for the PQC protocol.
This module provides server-side operations for the synchronous API.
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

/// Synchronous server for the PQC protocol.
pub struct PqcServer {
    session: PqcSession,
}

impl PqcServer {
    /// Create a new PQC server.
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(crate::core::session::state::Role::Server);
        Ok(Self { session })
    }

    /// Accept a connection from a client.
    /// Takes the client's public key and returns the ciphertext and verification key.
    pub fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        common::accept(&mut self.session, client_public_key)
    }

    /// Complete authentication with the client's verification key.
    pub fn authenticate(&mut self, client_verification_key: &[u8]) -> Result<()> {
        common::authenticate(&mut self.session, client_verification_key)
    }

    /// Send a message to the client.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        common::send(&mut self.session, data)
    }

    /// Receive a message from the client.
    pub fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        common::receive(&mut self.session, encrypted)
    }

    /// Close the connection.
    pub fn close(&mut self) -> Vec<u8> {
        common::close(&mut self.session)
    }

    /// Lazily stream data to the client without materializing all chunks at once.
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

    /// Check if key rotation is needed and initiate it if necessary.
    pub fn check_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        common::check_rotation(&mut self.session)
    }

    /// Process a key rotation message from the client.
    pub fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        common::process_rotation(&mut self.session, rotation_msg)
    }

    /// Complete key rotation based on the client's response.
    pub fn complete_rotation(&mut self, response: &[u8]) -> Result<()> {
        common::complete_rotation(&mut self.session, response)
    }

    /// Get the current connection state.
    pub fn state(&self) -> SessionState {
        common::state(&self.session)
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
}