/*!
Asynchronous client implementation for the PQC protocol.
This client uses a shared (Arc‑Mutex) session and delegates common operations to the common module.
*/

use crate::{
    error::{Result, Error},
    session::{PqcSession, Role, SessionState},
    constants::MAX_CHUNK_SIZE,
};
use crate::client::common;
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::future::Future;

use super::stream::{
    AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncStreamDataIterator,
};

/// Asynchronous client for the PQC protocol.
pub struct AsyncPqcClient {
    session: Arc<Mutex<PqcSession>>,
}

impl AsyncPqcClient {
    /// Create a new async PQC client.
    pub async fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Client);
        Ok(Self { session: Arc::new(Mutex::new(session)) })
    }

    /// Start the connection process asynchronously.
    pub async fn connect(&self) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::connect(&mut session)
    }

    /// Process the server's response asynchronously.
    pub async fn process_response(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::process_response(&mut session, ciphertext)
    }

    /// Complete authentication asynchronously with the server's verification key.
    pub async fn authenticate(&self, server_verification_key: &[u8]) -> Result<()> {
        let mut session = self.session.lock().unwrap();
        common::authenticate(&mut session, server_verification_key)
    }

    /// Send a message to the server asynchronously.
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::send(&mut session, data)
    }

    /// Receive a message from the server asynchronously.
    pub async fn receive(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().unwrap();
        common::receive(&mut session, encrypted)
    }

    /// Close the connection asynchronously.
    pub async fn close(&self) -> Vec<u8> {
        let mut session = self.session.lock().unwrap();
        common::close(&mut session)
    }

    /// Create a stream sender to stream data to the server.
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

    /// Stream data as bytes to the server.
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
    
    #[tokio::test]
    async fn test_client_init() -> Result<()> {
        let client = AsyncPqcClient::new().await?;
        let pk = client.connect().await?;
        // Check that the public key has the expected size.
        assert_eq!(pk.len(), pqcrypto_kyber::kyber768::public_key_bytes());
        Ok(())
    }
}
