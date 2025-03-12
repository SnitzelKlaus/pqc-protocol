/*!
Stream sender for the PQC protocol.

This module provides functionality for streaming large data in chunks.
*/

use crate::{
    constants::MAX_CHUNK_SIZE,
    error::{Error, Result},
    session::PqcSession,
};

use std::io::Read;

/// Helper for streaming data in chunks
///
/// This struct provides utilities for streaming large data
/// in manageable chunks using the PQC protocol.
pub struct StreamSender<'a> {
    /// Reference to the PQC session
    session: &'a mut PqcSession,
    
    /// Size of chunks to use for streaming
    chunk_size: usize,
}

impl<'a> StreamSender<'a> {
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
    pub fn stream_data(self, data: &'a [u8]) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        data.chunks(self.chunk_size)
            .map(move |chunk| self.session.encrypt_and_sign(chunk))
    }
    
    /// Stream a reader in chunks
    ///
    /// Takes a reader and processes its content in chunks, yielding encrypted
    /// chunks ready to be sent.
    pub fn stream_reader<'b, R: Read + 'b>(&'b mut self, reader: &'b mut R) -> StreamReader<'a, 'b, R> 
    where 'b: 'a {
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
    sender: &'b mut StreamSender<'a>,
    
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

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock session for testing
    fn create_mock_session() -> Result<PqcSession> {
        PqcSession::new()
    }
    
    #[test]
    fn test_stream_data() {
        // This test is just a placeholder since we can't easily create an established session
        // without going through key exchange and authentication
        let mut session = create_mock_session().unwrap();
        let sender = StreamSender::new(&mut session, Some(10));
        
        assert_eq!(sender.chunk_size(), 10);
    }
}