/*!
Streaming utilities for the PQC protocol.
*/

use crate::{
    error::{Error, Result},
    session::PqcSession,
    types::MAX_CHUNK_SIZE,
};

use std::io::{Read, Write};

/// Helper for streaming data in chunks
///
/// This struct provides utilities for streaming large data
/// in manageable chunks using the PQC protocol.
pub struct PqcStreamSender<'a> {
    /// Reference to the PQC session
    session: &'a mut PqcSession,
    
    /// Size of chunks to use for streaming
    chunk_size: usize,
}

impl<'a> PqcStreamSender<'a> {
    /// Create a new streaming helper
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
    pub fn stream_data<'b>(&'b mut self, data: &'b [u8]) -> impl Iterator<Item = Result<Vec<u8>>> + 'b {
        data.chunks(self.chunk_size)
            .map(move |chunk| self.session.encrypt_and_sign(chunk))
    }
    
    /// Stream a reader in chunks
    ///
    /// Takes a reader and processes its content in chunks, yielding encrypted
    /// chunks ready to be sent.
    pub fn stream_reader<'b, R: Read + 'b>(&'b mut self, reader: &'b mut R) -> StreamReader<'a, 'b, R> 
    where 'b: 'a {  // This is the key change - we're now requiring 'b to outlive 'a
        let buffer = vec![0; self.chunk_size];
        StreamReader {
            sender: self,
            reader,
            buffer,
        }
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

/// Helper for streaming from a reader
pub struct StreamReader<'a, 'b, R: Read> {
    /// Reference to the PQC stream sender
    sender: &'b mut PqcStreamSender<'a>,
    
    /// Reader to stream from
    reader: &'b mut R,
    
    /// Buffer for reading chunks
    buffer: Vec<u8>,
}

impl<'a, 'b, R: Read> Iterator for StreamReader<'a, 'b, R> {
    type Item = Result<Vec<u8>>;
    
    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read(&mut self.buffer) {
            Ok(0) => None, // End of stream
            Ok(n) => Some(self.sender.session.encrypt_and_sign(&self.buffer[..n])),
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

/// Helper for receiving streamed data
pub struct PqcStreamReceiver<'a> {
    /// Reference to the PQC session
    session: &'a mut PqcSession,
    
    /// Buffer for reassembling data if needed
    reassembly_buffer: Option<Vec<u8>>,
}

impl<'a> PqcStreamReceiver<'a> {
    /// Create a new streaming receiver
    pub fn new(session: &'a mut PqcSession) -> Self {
        Self {
            session,
            reassembly_buffer: None,
        }
    }
    
    /// Process a received encrypted chunk
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        self.session.verify_and_decrypt(chunk)
    }
    
    /// Write received chunks to a writer
    pub fn write_to<W: Write>(&mut self, writer: &mut W, chunk: &[u8]) -> Result<usize> {
        let decrypted = self.process_chunk(chunk)?;
        writer.write(&decrypted).map_err(Error::Io)
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
    
    /// Process a chunk and add to reassembly buffer if enabled
    pub fn process_chunk_with_reassembly(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        let decrypted = self.process_chunk(chunk)?;
        
        if let Some(ref mut buffer) = self.reassembly_buffer {
            buffer.extend_from_slice(&decrypted);
        }
        
        Ok(decrypted)
    }
    
    /// Get the current reassembly buffer contents
    pub fn reassembled_data(&self) -> Option<&[u8]> {
        self.reassembly_buffer.as_ref().map(|b| b.as_slice())
    }
    
    /// Take ownership of the reassembly buffer
    pub fn take_reassembled_data(&mut self) -> Option<Vec<u8>> {
        self.reassembly_buffer.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::PqcSession;
    
    // Mock session for testing
    fn create_mock_session() -> PqcSession {
        PqcSession::new().unwrap()
    }
    
    #[test]
    fn test_stream_data() {
        // This test is just a placeholder since we can't easily create an established session
        // without going through key exchange and authentication
        let mut session = create_mock_session();
        let sender = PqcStreamSender::new(&mut session, Some(10));
        
        assert_eq!(sender.chunk_size(), 10);
    }
}