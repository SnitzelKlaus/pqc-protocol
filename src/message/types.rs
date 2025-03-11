/*!
Message types for the PQC protocol.

This module defines the different types of messages that can be
exchanged in the protocol.
*/

use std::fmt;

/// Protocol message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Key exchange message
    KeyExchange = 0x01,
    /// Signature/authentication message
    Signature = 0x02,
    /// Data transfer message
    Data = 0x03,
    /// Acknowledgment message
    Ack = 0x04,
    /// Connection close message
    Close = 0x05,
    /// Error message
    Error = 0xFF,
}

impl MessageType {
    /// Convert a u8 value to a MessageType
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::KeyExchange),
            0x02 => Some(MessageType::Signature),
            0x03 => Some(MessageType::Data),
            0x04 => Some(MessageType::Ack),
            0x05 => Some(MessageType::Close),
            0xFF => Some(MessageType::Error),
            _ => None,
        }
    }
    
    /// Get the u8 value of this MessageType
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::KeyExchange => write!(f, "KeyExchange"),
            MessageType::Signature => write!(f, "Signature"),
            MessageType::Data => write!(f, "Data"),
            MessageType::Ack => write!(f, "Ack"),
            MessageType::Close => write!(f, "Close"),
            MessageType::Error => write!(f, "Error"),
        }
    }
}

/// Protocol error codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Protocol version mismatch
    VersionMismatch = 0x01,
    /// Invalid message format
    InvalidFormat = 0x02,
    /// Authentication failure
    AuthFailure = 0x03,
    /// Decryption failure
    DecryptionFailure = 0x04,
    /// Sequence number mismatch
    SequenceMismatch = 0x05,
    /// Internal error
    InternalError = 0x10,
}

impl ErrorCode {
    /// Convert a u8 value to an ErrorCode
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(ErrorCode::VersionMismatch),
            0x02 => Some(ErrorCode::InvalidFormat),
            0x03 => Some(ErrorCode::AuthFailure),
            0x04 => Some(ErrorCode::DecryptionFailure),
            0x05 => Some(ErrorCode::SequenceMismatch),
            0x10 => Some(ErrorCode::InternalError),
            _ => None,
        }
    }
    
    /// Get the u8 value of this ErrorCode
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::VersionMismatch => write!(f, "VersionMismatch"),
            ErrorCode::InvalidFormat => write!(f, "InvalidFormat"),
            ErrorCode::AuthFailure => write!(f, "AuthFailure"),
            ErrorCode::DecryptionFailure => write!(f, "DecryptionFailure"),
            ErrorCode::SequenceMismatch => write!(f, "SequenceMismatch"),
            ErrorCode::InternalError => write!(f, "InternalError"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(0x01), Some(MessageType::KeyExchange));
        assert_eq!(MessageType::from_u8(0x02), Some(MessageType::Signature));
        assert_eq!(MessageType::from_u8(0x03), Some(MessageType::Data));
        assert_eq!(MessageType::from_u8(0x04), Some(MessageType::Ack));
        assert_eq!(MessageType::from_u8(0x05), Some(MessageType::Close));
        assert_eq!(MessageType::from_u8(0xFF), Some(MessageType::Error));
        assert_eq!(MessageType::from_u8(0x06), None);
        
        assert_eq!(MessageType::KeyExchange.as_u8(), 0x01);
        assert_eq!(MessageType::Signature.as_u8(), 0x02);
        assert_eq!(MessageType::Data.as_u8(), 0x03);
        assert_eq!(MessageType::Ack.as_u8(), 0x04);
        assert_eq!(MessageType::Close.as_u8(), 0x05);
        assert_eq!(MessageType::Error.as_u8(), 0xFF);
    }

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(ErrorCode::from_u8(0x01), Some(ErrorCode::VersionMismatch));
        assert_eq!(ErrorCode::from_u8(0x02), Some(ErrorCode::InvalidFormat));
        assert_eq!(ErrorCode::from_u8(0x03), Some(ErrorCode::AuthFailure));
        assert_eq!(ErrorCode::from_u8(0x04), Some(ErrorCode::DecryptionFailure));
        assert_eq!(ErrorCode::from_u8(0x05), Some(ErrorCode::SequenceMismatch));
        assert_eq!(ErrorCode::from_u8(0x10), Some(ErrorCode::InternalError));
        assert_eq!(ErrorCode::from_u8(0x20), None);
        
        assert_eq!(ErrorCode::VersionMismatch.as_u8(), 0x01);
        assert_eq!(ErrorCode::InvalidFormat.as_u8(), 0x02);
        assert_eq!(ErrorCode::AuthFailure.as_u8(), 0x03);
        assert_eq!(ErrorCode::DecryptionFailure.as_u8(), 0x04);
        assert_eq!(ErrorCode::SequenceMismatch.as_u8(), 0x05);
        assert_eq!(ErrorCode::InternalError.as_u8(), 0x10);
    }
}