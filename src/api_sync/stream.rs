/*!
Synchronous streaming utilities for the PQC protocol.

This module provides utilities for streaming data using synchronous I/O,
building on the core streaming functionality but with additional
conveniences for synchronous operation.
*/

use std::io::{self, Read, Write};

use crate::{
    error::{Result, Error},
    session::PqcSession,
    constants::MAX_CHUNK_SIZE,
};

/// Enhanced synchronous stream sender for the PQC protocol
pub struct PqcSyncStreamSender<'a> {
    /// The underlying PQC session
    session: &'a mut PqcSession,
    
    /// Size of chunks to use for streaming
    chunk_size: usize,
}

impl<'a> PqcSyncStreamSender<'a> {
    /// Create a new synchronous stream sender
    pub fn new(session: &'a mut PqcSession, chunk_size: Option<usize>) -> Self {
        Self {
            session,
            chunk_size: chunk_size.unwrap_or(MAX_CHUNK_SIZE),
        }
    }
    
    /// Stream data in chunks
    ///
    /// Takes a byte slice and returns an iterator that yields encrypted
    /// chunks of data ready to be sent.
    pub fn stream_data(self, data: &'a [u8]) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        data.chunks(self.chunk_size)
            .map(move |chunk| self.session.encrypt_and_sign(chunk))
    }
    
    /// Stream from a reader in chunks
    ///
    /// Takes a reader and processes its content in chunks, returning an
    /// iterator that yields encrypted chunks ready to be sent.
    pub fn stream_reader<R: Read>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> impl Iterator<Item = Result<Vec<u8>>> + '_ {
        StreamIterator {
            sender: self,
            reader,
            buffer,
            finished: false,
        }
    }
    
    /// Stream data directly to a writer
    ///
    /// Reads data from a reader in chunks, encrypts each chunk,
    /// and writes the encrypted chunks to a writer.
    pub fn stream_to_writer<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        buffer: &mut [u8],
    ) -> Result<u64> {
        let mut total_written = 0;
        
        loop {
            // Read a chunk
            let bytes_read = reader.read(buffer)?;
            if bytes_read == 0 {
                break;
            }
            
            // Encrypt the chunk
            let encrypted = self.session.encrypt_and_sign(&buffer[..bytes_read])?;
            
            // Write the encrypted chunk
            writer.write_all(&encrypted)?;
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

/// Iterator for streaming from a reader
pub struct StreamIterator<'a, R: Read> {
    /// Reference to the PQC stream sender
    sender: &'a mut PqcSyncStreamSender<'a>,
    
    /// Reader to stream from
    reader: &'a mut R,
    
    /// Buffer for reading chunks
    buffer: &'a mut [u8],
    
    /// Whether the stream is finished
    finished: bool,
}

impl<'a, R: Read> Iterator for StreamIterator<'a, R> {
    type Item = Result<Vec<u8>>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        
        // Read a chunk
        let bytes_read = match self.reader.read(self.buffer) {
            Ok(0) => {
                self.finished = true;
                return None;
            }
            Ok(n) => n,
            Err(e) => {
                self.finished = true;
                return Some(Err(Error::Io(e)));
            }
        };
        
        // Encrypt the chunk
        match self.sender.session.encrypt_and_sign(&self.buffer[..bytes_read]) {
            Ok(encrypted) => Some(Ok(encrypted)),
            Err(e) => {
                self.finished = true;
                Some(Err(e))
            }
        }
    }
}

/// Enhanced synchronous stream receiver for the PQC protocol
pub struct PqcSyncStreamReceiver<'a> {
    /// The underlying PQC session
    session: &'a mut PqcSession,
    
    /// Buffer for reassembling data
    reassembly_buffer: Option<Vec<u8>>,
}

impl<'a> PqcSyncStreamReceiver<'a> {
    /// Create a new synchronous stream receiver
    pub fn new(session: &'a mut PqcSession) -> Self {
        Self {
            session,
            reassembly_buffer: None,
        }
    }
    
    /// Create a new synchronous stream receiver with reassembly enabled
    pub fn with_reassembly(session: &'a mut PqcSession) -> Self {
        Self {
            session,
            reassembly_buffer: Some(Vec::new()),
        }
    }
    
    /// Process a received encrypted chunk
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let decrypted = self.session.verify_and_decrypt(chunk)?;
        
        if let Some(ref mut buffer) = self.reassembly_buffer {
            buffer.extend_from_slice(&decrypted);
        }
        
        Ok(decrypted)
    }
    
    /// Process multiple encrypted chunks at once
    pub fn process_chunks<I: IntoIterator<Item = Vec<u8>>>(&mut self, chunks: I) -> Result<usize> {
        let mut total_size = 0;
        
        for chunk in chunks {
            let decrypted = self.process_chunk(&chunk)?;
            total_size += decrypted.len();
        }
        
        Ok(total_size)
    }
    
    /// Process chunks from a reader
    pub fn process_reader<R: Read>(&mut self, reader: &mut R) -> Result<usize> {
        let mut total_processed = 0;
        let mut header_buf = [0u8; 10]; // Header size
        
        loop {
            // Read header
            match reader.read_exact(&mut header_buf) {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            // Parse header
            let header = crate::message::MessageHeader::from_bytes(&header_buf)?;
            
            // Read payload
            let mut payload = vec![0u8; header.payload_len as usize];
            reader.read_exact(&mut payload)?;
            
            // Combine header and payload
            let mut message = Vec::with_capacity(header_buf.len() + payload.len());
            message.extend_from_slice(&header_buf);
            message.extend_from_slice(&payload);
            
            // Process the message
            let decrypted = self.process_chunk(&message)?;
            total_processed += decrypted.len();
        }
        
        Ok(total_processed)
    }
    
    /// Read chunks from a reader and write decrypted data to a writer
    pub fn process_to_writer<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total_written = 0;
        let mut header_buf = [0u8; 10]; // Header size
        
        loop {
            // Read header
            match reader.read_exact(&mut header_buf) {
                Ok(_) => {},
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            // Parse header
            let header = crate::message::MessageHeader::from_bytes(&header_buf)?;
            
            // Read payload
            let mut payload = vec![0u8; header.payload_len as usize];
            reader.read_exact(&mut payload)?;
            
            // Combine header and payload
            let mut message = Vec::with_capacity(header_buf.len() + payload.len());
            message.extend_from_slice(&header_buf);
            message.extend_from_slice(&payload);
            
            // Decrypt the message
            let decrypted = self.session.verify_and_decrypt(&message)?;
            
            // Write the decrypted data
            writer.write_all(&decrypted)?;
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

/// Extension trait for Read to use with PQC protocol
pub trait PqcReadExt: Read + Sized {
    /// Create a PQC encrypted reader
    fn pqc_encrypt<'a>(
        &'a mut self,
        session: &'a mut PqcSession,
        chunk_size: Option<usize>,
    ) -> PqcSyncStreamSender<'a> {
        PqcSyncStreamSender::new(session, chunk_size)
    }
}

impl<T: Read + Sized> PqcReadExt for T {}

/// Extension trait for Write to use with PQC protocol
pub trait PqcWriteExt: Write + Sized {
    /// Create a PQC decryption writer
    fn pqc_decrypt<'a>(
        &'a mut self,
        session: &'a mut PqcSession,
        reassemble: bool,
    ) -> PqcSyncStreamReceiver<'a> {
        if reassemble {
            PqcSyncStreamReceiver::with_reassembly(session)
        } else {
            PqcSyncStreamReceiver::new(session)
        }
    }
}

impl<T: Write + Sized> PqcWriteExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock session for testing
    fn create_test_session() -> Result<(PqcSession, PqcSession)> {
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
    
    #[test]
    fn test_stream_data() -> Result<()> {
        let (mut client, mut server) = create_test_session()?;
        
        // Create test data
        let data = vec![0u8; 100000]; // 100KB
        
        // Stream with chunks of 10KB
        let sender = PqcSyncStreamSender::new(&mut client, Some(10000));
        let mut receiver = PqcSyncStreamReceiver::with_reassembly(&mut server);
        
        // Process all chunks
        for encrypted in sender.stream_data(&data) {
            let encrypted = encrypted?;
            receiver.process_chunk(&encrypted)?;
        }
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_stream_reader() -> Result<()> {
        let (mut client, mut server) = create_test_session()?;
        
        // Create test data
        let data = vec![0u8; 50000]; // 50KB
        let mut cursor = std::io::Cursor::new(data.clone());
        
        // Create buffer
        let mut buffer = vec![0u8; 8192]; // 8KB buffer
        
        // Stream from reader
        let mut sender = PqcSyncStreamSender::new(&mut client, Some(8192));
        let mut receiver = PqcSyncStreamReceiver::with_reassembly(&mut server);
        
        // Process all chunks
        for encrypted in sender.stream_reader(&mut cursor, &mut buffer) {
            let encrypted = encrypted?;
            receiver.process_chunk(&encrypted)?;
        }
        
        // Verify reassembled data
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
    
    #[test]
    fn test_stream_to_writer() -> Result<()> {
        let (mut client, mut server) = create_test_session()?;
        
        // Create test data
        let data = vec![0u8; 30000]; // 30KB
        let mut reader = std::io::Cursor::new(data.clone());
        
        // Create buffer and output
        let mut buffer = vec![0u8; 5000]; // 5KB buffer
        let mut encrypted_output = Vec::new();
        
        // Stream to writer
        let mut sender = PqcSyncStreamSender::new(&mut client, Some(5000));
        sender.stream_to_writer(&mut reader, &mut encrypted_output, &mut buffer)?;
        
        // Process with receiver
        let mut receiver = PqcSyncStreamReceiver::with_reassembly(&mut server);
        let mut decrypted_output = Vec::new();
        
        // Read encrypted data
        let mut encrypted_reader = std::io::Cursor::new(encrypted_output);
        
        // Process to writer
        receiver.process_to_writer(&mut encrypted_reader, &mut decrypted_output)?;
        
        // Verify output
        assert_eq!(decrypted_output.len(), data.len());
        assert_eq!(decrypted_output, data);
        
        // Also check the reassembly buffer
        let reassembled = receiver.reassembled_data().unwrap();
        assert_eq!(reassembled.len(), data.len());
        assert_eq!(reassembled, &data[..]);
        
        Ok(())
    }
}