/*!
Message header implementation for the PQC protocol.
*/

use crate::{
    error::{Error, Result, format_err},
    types::{MessageType, sizes::HEADER_SIZE},
    VERSION,
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
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = self.version;
        bytes[1] = self.msg_type.as_u8();
        BigEndian::write_u32(&mut bytes[2..6], self.seq_num);
        BigEndian::write_u32(&mut bytes[6..10], self.payload_len);
        bytes
    }

    /// Parse a header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
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
        let mut bytes = [0u8; HEADER_SIZE];
        reader.read_exact(&mut bytes)?;
        Self::from_bytes(&bytes)
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
        let mut bytes = [0u8; HEADER_SIZE];
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
        let mut bytes = [0u8; HEADER_SIZE];
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
}