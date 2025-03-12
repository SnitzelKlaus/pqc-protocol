/*!
Asynchronous server implementation for the PQC protocol.
This module provides server-side operations for the asynchronous API.
*/

use crate::{
    error::{Result, Error},
    session::{PqcSession, Role, SessionState},
    constants::MAX_CHUNK_SIZE,
};
use crate::server::common;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::future::Future;

use crate::stream::{AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncStreamDataIterator};

/// Asynchronous server for the PQC protocol.
pub struct AsyncPqcServer {
    session: Arc<Mutex<PqcSession>>,
}

impl AsyncPqcServer {
    /// Create a new async PQC server.
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        Ok(Self { session: Arc::new(Mutex::new(session)) })
    }

    /// Accept a connection asynchronously.
    /// Takes the client's public key and returns the ciphertext and verification key.
    pub async fn accept(&self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut session = self.session.lock().unwrap();
        common::accept(&mut session, client_public_key)
    }

    /// Complete authentication asynchronously with the client's verification key.
    pub async fn authenticate(&self, client_verification_key: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        common::authenticate(&mut session, client_verification_key)
    }

    /// Send a message to the client asynchronously.
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::send(&mut session, data)
    }

    /// Receive a message from the client asynchronously.
    pub async fn receive(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::receive(&mut session, encrypted)
    }

    /// Close the connection asynchronously.
    pub async fn close(&self) -> Vec<u8> {
        let mut session = self.session.lock().unwrap();
        common::close(&mut session)
    }

    /// Create a stream sender to stream data to the client.
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

    /// Stream data as bytes to the client.
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
    pub fn state(&self) -> Result<SessionState> {
        let session = self.session.lock().unwrap();
        Ok(session.state())
    }

    /// Execute a function that requires mutable access to the session.
    pub async fn with_session<F, Fut, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PqcSession) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        let mut session = self.session.lock().unwrap();
        let future = f(&mut session);
        // Drop the lock before awaiting to avoid deadlocks.
        drop(session);
        future.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_async::AsyncPqcClient;
    
    #[tokio::test]
    async fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let client = crate::api_async::AsyncPqcClient::new().await?;
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
