/*!
Message format definitions for the PQC protocol.

This module defines the structure and format of protocol messages,
including serialization and deserialization.
*/

use crate::{
    constants::{VERSION, sizes},
    error::{Error, Result, format_err},
    message::types::MessageType,
};
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, Read, Write};

/// Protocol message header (10 bytes)
///
/// The header has the following format:
/// - Version (1 byte): Protocol version, currently 0x01
/// - Message Type (1 byte): Type of message (see MessageType enum)
/// - Sequence Number (4 bytes, big-endian): Message sequence number
/// - Payload Length (4 bytes, big-endian): Length of the payload in bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// Protocol version
    pub version: u8,
    /// Message type
    pub msg_type: MessageType,
    /// Sequence number
    pub seq_num: u32,
    /// Payload length
    pub payload_len: u32,
}

impl MessageHeader {
    /// Create a new message header
    pub fn new(msg_type: MessageType, seq_num: u32, payload_len: u32) -> Self {
        Self {
            version: VERSION,
            msg_type,
            seq_num,
            payload_len,
        }
    }

    /// Convert the header to bytes (10 bytes)
    pub fn to_bytes(&self) -> [u8; sizes::HEADER_SIZE] {
        let mut bytes = [0u8; sizes::HEADER_SIZE];
        bytes[0] = self.version;
        bytes[1] = self.msg_type.as_u8();
        BigEndian::write_u32(&mut bytes[2..6], self.seq_num);
        BigEndian::write_u32(&mut bytes[6..10], self.payload_len);
        bytes
    }

    /// Parse a header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < sizes::HEADER_SIZE {
            return format_err("Header too short");
        }

        let version = bytes[0];
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let msg_type = match MessageType::from_u8(bytes[1]) {
            Some(t) => t,
            None => return format_err(format!("Invalid message type: {}", bytes[1])),
        };

        let seq_num = BigEndian::read_u32(&bytes[2..6]);
        let payload_len = BigEndian::read_u32(&bytes[6..10]);

        Ok(Self {
            version,
            msg_type,
            seq_num,
            payload_len,
        })
    }

    /// Write the header to a writer
    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Read a header from a reader
    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = [0u8; sizes::HEADER_SIZE];
        reader.read_exact(&mut bytes)?;
        Self::from_bytes(&bytes)
    }
}

/// Message builder for constructing protocol messages
pub struct MessageBuilder {
    header: MessageHeader,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(msg_type: MessageType, seq_num: u32) -> Self {
        Self {
            header: MessageHeader::new(msg_type, seq_num, 0),
            payload: Vec::new(),
            signature: None,
        }
    }
    
    /// Set the payload
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }
    
    /// Add signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
    
    /// Build the message
    pub fn build(mut self) -> Vec<u8> {
        let payload_len = self.payload.len() + self.signature.as_ref().map_or(0, |s| s.len());
        self.header.payload_len = payload_len as u32;
        
        let mut message = Vec::with_capacity(sizes::HEADER_SIZE + payload_len);
        message.extend_from_slice(&self.header.to_bytes());
        message.extend_from_slice(&self.payload);
        
        if let Some(signature) = self.signature {
            message.extend_from_slice(&signature);
        }
        
        message
    }
}

/// Message parser for extracting parts of a message
pub struct MessageParser<'a> {
    data: &'a [u8],
    header: MessageHeader,
}

impl<'a> MessageParser<'a> {
    /// Parse a message from bytes
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < sizes::HEADER_SIZE {
            return format_err("Message too short for header");
        }
        
        let header = MessageHeader::from_bytes(&data[..sizes::HEADER_SIZE])?;
        
        if data.len() < sizes::HEADER_SIZE + header.payload_len as usize {
            return format_err("Message too short for payload");
        }
        
        Ok(Self {
            data,
            header,
        })
    }
    
    /// Get the header
    pub fn header(&self) -> &MessageHeader {
        &self.header
    }
    
    /// Get the payload without the signature
    pub fn payload(&self, signature_len: usize) -> Result<&'a [u8]> {
        let payload_end = sizes::HEADER_SIZE + self.header.payload_len as usize;
        
        if self.header.payload_len as usize <= signature_len {
            return format_err("Payload too small to contain signature");
        }
        
        let data_end = payload_end - signature_len;
        Ok(&self.data[sizes::HEADER_SIZE..data_end])
    }
    
    /// Get the signature
    pub fn signature(&self, signature_len: usize) -> Result<&'a [u8]> {
        let payload_end = sizes::HEADER_SIZE + self.header.payload_len as usize;
        
        if self.header.payload_len as usize <= signature_len {
            return format_err("Payload too small to contain signature");
        }
        
        let data_end = payload_end - signature_len;
        Ok(&self.data[data_end..payload_end])
    }
    
    /// Get the raw message data
    pub fn raw_data(&self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let header = MessageHeader::new(MessageType::Data, 42, 100);
        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).unwrap();
        
        assert_eq!(header, parsed);
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.msg_type, MessageType::Data);
        assert_eq!(parsed.seq_num, 42);
        assert_eq!(parsed.payload_len, 100);
    }

    #[test]
    fn test_header_invalid_version() {
        let mut bytes = [0u8; sizes::HEADER_SIZE];
        bytes[0] = 0xFF; // Invalid version
        bytes[1] = MessageType::Data.as_u8();
        
        let result = MessageHeader::from_bytes(&bytes);
        assert!(result.is_err());
        
        if let Err(Error::UnsupportedVersion(ver)) = result {
            assert_eq!(ver, 0xFF);
        } else {
            panic!("Expected UnsupportedVersion error");
        }
    }

    #[test]
    fn test_header_invalid_type() {
        let mut bytes = [0u8; sizes::HEADER_SIZE];
        bytes[0] = VERSION;
        bytes[1] = 0x42; // Invalid message type
        
        let result = MessageHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_too_short() {
        let bytes = [0u8; 5]; // Too short
        let result = MessageHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_message_builder() {
        let payload = vec![1, 2, 3, 4];
        let signature = vec![5, 6, 7, 8];
        
        let message = MessageBuilder::new(MessageType::Data, 42)
            .with_payload(payload.clone())
            .with_signature(signature.clone())
            .build();
        
        assert_eq!(message.len(), sizes::HEADER_SIZE + payload.len() + signature.len());
        
        let parser = MessageParser::new(&message).unwrap();
        assert_eq!(parser.header().msg_type, MessageType::Data);
        assert_eq!(parser.header().seq_num, 42);
        assert_eq!(parser.header().payload_len as usize, payload.len() + signature.len());
        
        let parsed_payload = parser.payload(signature.len()).unwrap();
        let parsed_signature = parser.signature(signature.len()).unwrap();
        
        assert_eq!(parsed_payload, payload);
        assert_eq!(parsed_signature, signature);
    }
}