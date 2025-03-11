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
use std::sync::Arc;
use futures::task::AtomicWaker;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    error::{Result, Error},
    session::PqcSession,
    constants::MAX_CHUNK_SIZE,
};

/// Asynchronous stream sender for the PQC protocol
pub struct AsyncPqcStreamSender<'a> {
    /// The underlying PQC session
    session: &'a mut PqcSession,
    
    /// Size of chunks to use for streaming
    chunk_size: usize,
}

impl<'a> AsyncPqcStreamSender<'a> {
    /// Create a new async stream sender
    pub fn new(session: &'a mut PqcSession, chunk_size: Option<usize>) -> Self {
        Self {
            session,
            chunk_size: chunk_size.unwrap_or(MAX_CHUNK_SIZE),
        }
    }
    
    /// Stream a byte slice as encrypted chunks
    pub fn stream_data<'b>(self, data: &'b [u8]) -> StreamDataIterator<'a, 'b> {
        StreamDataIterator {
            sender: self,
            data,
            position: 0,
        }
    }
    
    /// Stream from an async reader
    pub async fn stream_reader<R>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> AsyncStreamReader<'_, R>
    where
        R: AsyncRead + Unpin,
    {
        AsyncStreamReader {
            sender: self,
            reader,
            buffer,
            finished: false,
            waker: Arc::new(AtomicWaker::new()),
            processing: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Stream data directly to an async writer
    pub async fn stream_to_writer<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut total_written = 0;
        
        loop {
            // Read a chunk
            let bytes_read = reader.read(buffer).await?;
            if bytes_read == 0 {
                break;
            }
            
            // Encrypt the chunk
            let encrypted = self.session.encrypt_and_sign(&buffer[..bytes_read])?;
            
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

/// Iterator for streaming data in chunks
pub struct StreamDataIterator<'a, 'b> {
    /// The stream sender
    sender: AsyncPqcStreamSender<'a>,
    
    /// Data to stream
    data: &'b [u8],
    
    /// Current position in the data
    position: usize,
}

impl<'a, 'b> Stream for StreamDataIterator<'a, 'b> {
    type Item = Result<Vec<u8>>;
    
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.position >= self.data.len() {
            return Poll::Ready(None);
        }
        
        let end = std::cmp::min(self.position + self.sender.chunk_size, self.data.len());
        let chunk = &self.data[self.position..end];
        self.position = end;
        
        match self.sender.session.encrypt_and_sign(chunk) {
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
    sender: &'a mut AsyncPqcStreamSender<'a>,
    
    /// Reader to stream from
    reader: &'a mut R,
    
    /// Buffer for reading
    buffer: &'a mut [u8],
    
    /// Whether we've reached the end of the stream
    finished: bool,
    
    /// Waker for async notifications
    waker: Arc<AtomicWaker>,
    
    /// Flag indicating if we're currently processing
    processing: Arc<AtomicBool>,
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
        let poll_read = Pin::new(&mut self.reader).poll_read(cx, self.buffer);
        
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
                match self.sender.session.encrypt_and_sign(chunk) {
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

/// Async stream receiver for the PQC protocol
pub struct AsyncPqcStreamReceiver<'a> {
    /// The underlying PQC session
    session: &'a mut PqcSession,
    
    /// Buffer for reassembling data
    reassembly_buffer: Option<Vec<u8>>,
}

impl<'a> AsyncPqcStreamReceiver<'a> {
    /// Create a new async stream receiver
    pub fn new(session: &'a mut PqcSession) -> Self {
        Self {
            session,
            reassembly_buffer: None,
        }
    }
    
    /// Create a new async stream receiver with reassembly enabled
    pub fn with_reassembly(session: &'a mut PqcSession) -> Self {
        Self {
            session,
            reassembly_buffer: Some(Vec::new()),
        }
    }
    
    /// Process a received encrypted chunk
    pub async fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let decrypted = self.session.verify_and_decrypt(chunk)?;
        
        if let Some(ref mut buffer) = self.reassembly_buffer {
            buffer.extend_from_slice(&decrypted);
        }
        
        Ok(decrypted)
    }
    
    /// Process multiple encrypted chunks
    pub async fn process_chunks<I, F>(&mut self, chunks: I) -> Result<usize>
    where
        I: IntoIterator<Item = F>,
        F: std::future::Future<Output = Result<Vec<u8>>>,
    {
        let mut total_size = 0;
        
        for chunk_future in chunks {
            let chunk = chunk_future.await?;
            let decrypted = self.process_chunk(&chunk).await?;
            total_size += decrypted.len();
        }
        
        Ok(total_size)
    }
    
    /// Read and process from an async reader
    pub async fn process_reader<R>(&mut self, reader: &mut R) -> Result<usize>
    where
        R: AsyncRead + Unpin,
    {
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
    
    /// Read chunks from a reader and write decrypted data to a writer
    pub async fn process_to_writer<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut total_written = 0;
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
            
            // Decrypt the message
            let decrypted = self.process_chunk(&message).await?;
            
            // Write the decrypted data
            writer.write_all(&decrypted).await?;
            total_written += decrypted.len() as u64;
            
            // Add to reassembly buffer if enabled
            if let Some(ref mut buffer) = self.reassembly_buffer {
                buffer.extend_from_slice(&decrypted);
            }
        }
        
        Ok(total_written)
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
    
    /// Get the size of the reassembly buffer
    pub fn reassembled_size(&self) -> usize {
        self.reassembly_buffer.as_ref().map_or(0, |b| b.len())
    }
}

/// Extension trait for AsyncRead to use with PQC protocol
pub trait AsyncPqcReadExt: AsyncRead + Sized {
    /// Create a PQC encrypted stream from this reader
    fn pqc_encrypt<'a>(
        &'a mut self,
        session: &'a mut PqcSession,
        chunk_size: Option<usize>,
    ) -> AsyncPqcStreamSender<'a> {
        AsyncPqcStreamSender::new(session, chunk_size)
    }
}

impl<T: AsyncRead + Sized> AsyncPqcReadExt for T {}

/// Extension trait for AsyncWrite to use with PQC protocol
pub trait AsyncPqcWriteExt: AsyncWrite + Sized {
    /// Create a PQC decrypted writer from this writer
    fn pqc_decrypt<'a>(
        &'a mut self,
        session: &'a mut PqcSession,
        reassemble: bool,
    ) -> AsyncPqcStreamReceiver<'a> {
        if reassemble {
            AsyncPqcStreamReceiver::with_reassembly(session)
        } else {
            AsyncPqcStreamReceiver::new(session)
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
    async fn test_stream_data() -> Result<()> {
        let (mut client, mut server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 100000]; // 100KB
        
        // Stream with chunks of 10KB
        let sender = AsyncPqcStreamSender::new(&mut client, Some(10000));
        let mut receiver = AsyncPqcStreamReceiver::with_reassembly(&mut server);
        
        // Process all chunks
        let mut stream = sender.stream_data(&data);
        while let Some(encrypted_result) = stream.next().await {
            let encrypted = encrypted_result?;
            receiver.process_chunk(&encrypted).await?;
        }
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_stream_reader() -> Result<()> {
        let (mut client, mut server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 50000]; // 50KB
        let mut cursor = tokio::io::Cursor::new(data.clone());
        
        // Create buffer
        let mut buffer = vec![0u8; 8192]; // 8KB buffer
        
        // Stream from reader
        let mut sender = AsyncPqcStreamSender::new(&mut client, Some(8192));
        let reader_stream = sender.stream_reader(&mut cursor, &mut buffer).await;
        let mut receiver = AsyncPqcStreamReceiver::with_reassembly(&mut server);
        
        // Process all chunks
        tokio::pin!(reader_stream);
        while let Some(encrypted_result) = reader_stream.next().await {
            let encrypted = encrypted_result?;
            receiver.process_chunk(&encrypted).await?;
        }
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_stream_to_writer() -> Result<()> {
        let (mut client, mut server) = create_test_session().await?;
        
        // Create test data
        let data = vec![0u8; 30000]; // 30KB
        let mut reader = tokio::io::Cursor::new(data.clone());
        
        // Create buffer and output
        let mut buffer = vec![0u8; 5000]; // 5KB buffer
        let mut encrypted_output = Vec::new();
        
        // Stream to writer
        let mut sender = AsyncPqcStreamSender::new(&mut client, Some(5000));
        sender.stream_to_writer(&mut reader, &mut encrypted_output, &mut buffer).await?;
        
        // Process with receiver
        let mut receiver = AsyncPqcStreamReceiver::with_reassembly(&mut server);
        let mut decrypted_output = Vec::new();
        
        // Read encrypted data
        let mut encrypted_reader = tokio::io::Cursor::new(encrypted_output);
        
        // Process to writer
        receiver.process_to_writer(&mut encrypted_reader, &mut decrypted_output).await?;
        
        // Verify output
        assert_eq!(decrypted_output.len(), data.len());
        assert_eq!(decrypted_output, data);
        
        // Also check the reassembly buffer
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_extension_traits() -> Result<()> {
        let (mut client, mut server) = create_test_session().await?;
        
        // Test data
        let data = b"Testing AsyncPqcReadExt and AsyncPqcWriteExt traits".to_vec();
        let mut reader = tokio::io::Cursor::new(data.clone());
        
        // Use extension traits
        let sender = reader.pqc_encrypt(&mut client, Some(16));
        
        // Verify the sender was created with correct chunk size
        assert_eq!(sender.chunk_size(), 16);
        
        Ok(())
    }
}