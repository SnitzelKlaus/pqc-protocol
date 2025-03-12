/*!
Stream receiver for the PQC protocol.

This module provides functionality for receiving streamed data
and optional reassembly.
*/

use crate::core::{
    error::{Error, Result},
    session::PqcSession,
};

use std::io::Write;

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
    
    /// Create a new streaming receiver with reassembly enabled
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

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock session for testing
    fn create_mock_session() -> Result<PqcSession> {
        PqcSession::new()
    }
    
    #[test]
    fn test_reassembly_flags() {
        let mut session = create_mock_session().unwrap();
        
        // Test with default constructor (no reassembly)
        let mut receiver = PqcStreamReceiver::new(&mut session);
        assert!(receiver.reassembly_buffer.is_none());
        
        // Enable reassembly
        receiver.enable_reassembly();
        assert!(receiver.reassembly_buffer.is_some());
        
        // Disable reassembly
        receiver.disable_reassembly();
        assert!(receiver.reassembly_buffer.is_none());
        
        // Test with reassembly constructor
        let receiver_with_reassembly = PqcStreamReceiver::with_reassembly(&mut session);
        assert!(receiver_with_reassembly.reassembly_buffer.is_some());
    }
}