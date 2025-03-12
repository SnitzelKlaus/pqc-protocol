/*!
Asynchronous streaming utilities for the PQC protocol.

This module provides utilities for streaming data using asynchronous I/O,
leveraging Tokio's async/await capabilities.
*/

use tokio::io::{self, AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{Stream, StreamExt, ready};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use futures::task::AtomicWaker;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    error::{Result, Error},
    session::PqcSession,
    constants::MAX_CHUNK_SIZE,
};

/// Iterator for streaming data in chunks
pub struct AsyncStreamDataIterator<'a> {
    /// The shared session
    pub(crate) session: Arc<Mutex<PqcSession>>,
    
    /// Data to stream
    pub(crate) data: &'a [u8],
    
    /// Current position in the data
    pub(crate) position: usize,
    
    /// Size of chunks to use
    pub(crate) chunk_size: usize,
}

impl<'a> Stream for AsyncStreamDataIterator<'a> {
    type Item = Result<Vec<u8>>;
    
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.position >= self.data.len() {
            return Poll::Ready(None);
        }
        
        let end = std::cmp::min(self.position + self.chunk_size, self.data.len());
        let chunk = &self.data[self.position..end];
        self.position = end;
        
        let mut session = match self.session.lock() {
            Ok(s) => s,
            Err(_) => return Poll::Ready(Some(Err(Error::Internal("Failed to lock session".into())))),
        };
        
        match session.encrypt_and_sign(chunk) {
            Ok(encrypted) => Poll::Ready(Some(Ok(encrypted))),
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}

/// Async stream reader for reading from AsyncRead sources
pub struct AsyncStreamReader<'a, R>
where
    R: AsyncRead + Unpin,
{
    /// Reference to the sender
    pub(crate) session: Arc<Mutex<PqcSession>>,
    
    /// Reader to stream from
    pub(crate) reader: &'a mut R,
    
    /// Buffer for reading
    pub(crate) buffer: Vec<u8>,
    
    /// Whether we've reached the end of the stream
    pub(crate) finished: bool,
    
    /// Waker for async notifications
    pub(crate) waker: Arc<AtomicWaker>,
    
    /// Flag indicating if we're currently processing
    pub(crate) processing: Arc<AtomicBool>,
    
    /// Chunk size for reading
    pub(crate) chunk_size: usize,
}

impl<'a, R> Stream for AsyncStreamReader<'a, R>
where
    R: AsyncRead + Unpin,
{
    type Item = Result<Vec<u8>>;
    
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }
        
        // Register waker
        self.waker.register(cx.waker());
        
        // Check if we're already processing
        if self.processing.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        
        // Mark as processing
        self.processing.store(true, Ordering::SeqCst);
        
        // Read from the reader
        let poll_read = Pin::new(&mut self.reader).poll_read(cx, &mut self.buffer);
        
        match poll_read {
            Poll::Ready(Ok(0)) => {
                // End of stream
                self.finished = true;
                self.processing.store(false, Ordering::SeqCst);
                Poll::Ready(None)
            }
            Poll::Ready(Ok(n)) => {
                // Process the chunk
                let chunk = &self.buffer[..n];
                
                let mut session = match self.session.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        self.processing.store(false, Ordering::SeqCst);
                        return Poll::Ready(Some(Err(Error::Internal("Failed to lock session".into()))));
                    }
                };
                
                match session.encrypt_and_sign(chunk) {
                    Ok(encrypted) => {
                        self.processing.store(false, Ordering::SeqCst);
                        Poll::Ready(Some(Ok(encrypted)))
                    }
                    Err(e) => {
                        self.processing.store(false, Ordering::SeqCst);
                        Poll::Ready(Some(Err(e)))
                    }
                }
            }
            Poll::Ready(Err(e)) => {
                // Error reading
                self.finished = true;
                self.processing.store(false, Ordering::SeqCst);
                Poll::Ready(Some(Err(Error::Io(e))))
            }
            Poll::Pending => {
                self.processing.store(false, Ordering::SeqCst);
                Poll::Pending
            }
        }
    }
}

/// Asynchronous stream sender for the PQC protocol
pub struct AsyncPqcStreamSender<'a, R>
where
    R: AsyncRead + Unpin,
{
    /// Reader to stream from
    pub(crate) reader: &'a mut R,
    
    /// The shared session
    pub(crate) session: Arc<Mutex<PqcSession>>,
    
    /// Size of chunks to use for streaming
    pub(crate) chunk_size: usize,
}

impl<'a, R> AsyncPqcStreamSender<'a, R>
where
    R: AsyncRead + Unpin,
{
    /// Create a stream reader
    pub async fn stream_reader(&mut self) -> AsyncStreamReader<'a, R> {
        AsyncStreamReader {
            session: self.session.clone(),
            reader: self.reader,
            buffer: vec![0; self.chunk_size],
            finished: false,
            waker: Arc::new(AtomicWaker::new()),
            processing: Arc::new(AtomicBool::new(false)),
            chunk_size: self.chunk_size,
        }
    }
    
    /// Copy all data from the reader to a writer
    pub async fn copy_to<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<u64> {
        let mut total_written = 0;
        let mut buffer = vec![0; self.chunk_size];
        
        loop {
            // Read a chunk
            let bytes_read = self.reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            
            // Encrypt the chunk
            let encrypted = {
                let mut session = self.session.lock().unwrap();
                session.encrypt_and_sign(&buffer[..bytes_read])?
            };
            
            // Write the encrypted chunk
            writer.write_all(&encrypted).await?;
            total_written += encrypted.len() as u64;
        }
        
        Ok(total_written)
    }
    
    /// Get the chunk size
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
    
    /// Set a new chunk size
    pub fn set_chunk_size(&mut self, size: usize) {
        self.chunk_size = size;
    }
}

/// Asynchronous stream receiver for the PQC protocol
pub struct AsyncPqcStreamReceiver<'a, W>
where
    W: AsyncWrite + Unpin,
{
    /// Writer to write to
    pub(crate) writer: &'a mut W,
    
    /// The shared session
    pub(crate) session: Arc<Mutex<PqcSession>>,
    
    /// Buffer for reassembling data
    pub(crate) reassembly_buffer: Option<Vec<u8>>,
}

impl<'a, W> AsyncPqcStreamReceiver<'a, W>
where
    W: AsyncWrite + Unpin,
{
    /// Process a received encrypted chunk
    pub async fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        // Decrypt the chunk
        let decrypted = {
            let mut session = self.session.lock().unwrap();
            session.verify_and_decrypt(chunk)?
        };
        
        // Write to the underlying writer
        self.writer.write_all(&decrypted).await?;
        
        // Add to reassembly buffer if enabled
        if let Some(ref mut buffer) = self.reassembly_buffer {
            buffer.extend_from_slice(&decrypted);
        }
        
        Ok(decrypted)
    }
    
    /// Process chunks from a stream
    pub async fn process_chunks<S, F>(&mut self, chunks: S) -> Result<usize>
    where
        S: Stream<Item = F> + Unpin,
        F: futures::Future<Output = Result<Vec<u8>>>,
    {
        let mut total_size = 0;
        tokio::pin!(chunks);
        
        while let Some(chunk_future) = chunks.next().await {
            let chunk = chunk_future.await?;
            let decrypted = self.process_chunk(&chunk).await?;
            total_size += decrypted.len();
        }
        
        Ok(total_size)
    }
    
    /// Process chunks from a reader
    pub async fn process_reader<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<usize> {
        let mut total_processed = 0;
        let mut header_buf = [0u8; 10]; // Header size
        
        loop {
            // Read header
            match reader.read_exact(&mut header_buf).await {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            // Parse header
            let header = crate::message::MessageHeader::from_bytes(&header_buf)?;
            
            // Read payload
            let mut payload = vec![0u8; header.payload_len as usize];
            reader.read_exact(&mut payload).await?;
            
            // Combine header and payload
            let mut message = Vec::with_capacity(header_buf.len() + payload.len());
            message.extend_from_slice(&header_buf);
            message.extend_from_slice(&payload);
            
            // Process the message
            let decrypted = self.process_chunk(&message).await?;
            total_processed += decrypted.len();
        }
        
        Ok(total_processed)
    }
    
    /// Enable reassembly of chunks into a single buffer
    pub fn enable_reassembly(&mut self) {
        if self.reassembly_buffer.is_none() {
            self.reassembly_buffer = Some(Vec::new());
        }
    }
    
    /// Disable reassembly and clear the buffer
    pub fn disable_reassembly(&mut self) {
        self.reassembly_buffer = None;
    }
    
    /// Get the current reassembly buffer contents
    pub fn reassembled_data(&self) -> Option<&[u8]> {
        self.reassembly_buffer.as_ref().map(|b| b.as_slice())
    }
    
    /// Take ownership of the reassembly buffer
    pub fn take_reassembled_data(&mut self) -> Option<Vec<u8>> {
        self.reassembly_buffer.take()
    }
    
    /// Clear the reassembly buffer without disabling reassembly
    pub fn clear_buffer(&mut self) {
        if let Some(ref mut buffer) = self.reassembly_buffer {
            buffer.clear();
        }
    }
    
    /// Get the size of the reassembled data
    pub fn reassembled_size(&self) -> usize {
        self.reassembly_buffer.as_ref().map_or(0, |b| b.len())
    }
    
    /// Flush the writer
    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await.map_err(Error::Io)
    }
}

/// Extension trait for AsyncRead to use with PQC protocol
pub trait AsyncPqcReadExt: AsyncRead + Sized {
    /// Create a PQC encrypted stream from this reader
    fn pqc_encrypt<'a>(
        &'a mut self,
        session: Arc<Mutex<PqcSession>>,
        chunk_size: Option<usize>,
    ) -> AsyncPqcStreamSender<'a, Self> {
        AsyncPqcStreamSender {
            reader: self,
            session,
            chunk_size: chunk_size.unwrap_or(MAX_CHUNK_SIZE),
        }
    }
}

impl<T: AsyncRead + Sized> AsyncPqcReadExt for T {}

/// Extension trait for AsyncWrite to use with PQC protocol
pub trait AsyncPqcWriteExt: AsyncWrite + Sized {
    /// Create a PQC decrypted writer
    fn pqc_decrypt<'a>(
        &'a mut self,
        session: Arc<Mutex<PqcSession>>,
        reassemble: bool,
    ) -> AsyncPqcStreamReceiver<'a, Self> {
        AsyncPqcStreamReceiver {
            writer: self,
            session,
            reassembly_buffer: if reassemble { Some(Vec::new()) } else { None },
        }
    }
}

impl<T: AsyncWrite + Sized> AsyncPqcWriteExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use futures::StreamExt;
    
    // Helper to create a test session
    async fn create_test_session() -> Result<(PqcSession, PqcSession)> {
        let mut client = PqcSession::new()?;
        let mut server = PqcSession::new()?;
        server.set_role(crate::session::Role::Server);
        
        // Key exchange
        let client_pk = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_pk)?;
        client.process_key_exchange(&ciphertext)?;
        
        // Authentication
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        Ok((client, server))
    }
    
    #[tokio::test]
    async fn test_stream_data_iterator() -> Result<()> {
        let (client, _server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 100000]; // 100KB
        
        // Create a shared session
        let session = Arc::new(Mutex::new(client));
        
        // Create stream iterator with 10KB chunks
        let mut stream_iter = AsyncStreamDataIterator {
            session: session.clone(),
            data: &data,
            position: 0,
            chunk_size: 10000,
        };
        
        // Count the number of chunks
        let mut chunk_count = 0;
        let mut total_size = 0;
        
        while let Some(chunk_result) = stream_iter.next().await {
            let encrypted = chunk_result?;
            total_size += encrypted.len();
            chunk_count += 1;
        }
        
        // We should have 10 chunks (100KB / 10KB)
        assert_eq!(chunk_count, 10);
        assert!(total_size > data.len()); // Encrypted data is larger due to headers and signatures
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_stream_reader() -> Result<()> {
        let (client, server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 50000]; // 50KB
        let mut cursor = tokio::io::Cursor::new(data.clone());
        
        // Create shared sessions
        let client_session = Arc::new(Mutex::new(client));
        let server_session = Arc::new(Mutex::new(server));
        
        // Create a sender
        let mut sender = AsyncPqcStreamSender {
            reader: &mut cursor,
            session: client_session,
            chunk_size: 8192, // 8KB chunks
        };
        
        // Get a stream reader
        let reader_stream = sender.stream_reader().await;
        
        // Create an output buffer
        let mut output = Vec::new();
        
        // Create a receiver
        let mut receiver = AsyncPqcStreamReceiver {
            writer: &mut output,
            session: server_session,
            reassembly_buffer: Some(Vec::new()),
        };
        
        // Process all chunks
        tokio::pin!(reader_stream);
        while let Some(encrypted_result) = reader_stream.next().await {
            let encrypted = encrypted_result?;
            receiver.process_chunk(&encrypted).await?;
        }
        
        // Verify output data
        assert_eq!(output.len(), data.len());
        assert_eq!(output, data);
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_copy_to() -> Result<()> {
        let (client, server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 30000]; // 30KB
        let mut source = tokio::io::Cursor::new(data.clone());
        
        // Create shared sessions
        let client_session = Arc::new(Mutex::new(client));
        let server_session = Arc::new(Mutex::new(server));
        
        // Create a (client, server) duplex pipe
        let (mut client_write, mut server_read) = tokio::io::duplex(65536);
        
        // Create a sender that wraps the source
        let mut sender = AsyncPqcStreamSender {
            reader: &mut source,
            session: client_session,
            chunk_size: 5000, // 5KB chunks
        };
        
        // Create a receiver that reassembles data
        let mut output = Vec::new();
        let mut receiver = AsyncPqcStreamReceiver {
            writer: &mut output,
            session: server_session,
            reassembly_buffer: Some(Vec::new()),
        };
        
        // Copy data from source to pipe
        let sent = sender.copy_to(&mut client_write).await?;
        
        // Process incoming data from pipe
        let received = receiver.process_reader(&mut server_read).await?;
        
        // Verify output
        assert_eq!(output.len(), data.len());
        assert_eq!(output, data);
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_extension_traits() -> Result<()> {
        let (client, server) = create_test_session().await?;
        
        // Create shared sessions
        let client_session = Arc::new(Mutex::new(client));
        let server_session = Arc::new(Mutex::new(server));
        
        // Test data
        let data = b"Testing AsyncPqcReadExt and AsyncPqcWriteExt traits".to_vec();
        let mut reader = tokio::io::Cursor::new(data.clone());
        
        // Use extension traits
        let mut sender = reader.pqc_encrypt(client_session, Some(16));
        
        // Verify the sender was created with correct chunk size
        assert_eq!(sender.chunk_size(), 16);
        
        // Create output and receiver
        let mut output = Vec::new();
        let mut receiver = output.pqc_decrypt(server_session, true);
        
        // Copy data
        let sent = sender.copy_to(&mut tokio::io::Cursor::new(Vec::new())).await?;
        
        Ok(())
    }
}