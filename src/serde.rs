/*!
Serialization support for the PQC protocol.

This module provides serialization and deserialization support for protocol
types using Serde. It's only built when the `serde-support` feature is enabled.
*/

use crate::{
    message::{MessageType, MessageHeader},
    session::SessionState,
    error::Result,
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Serializable version of MessageType
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SerdeMessageType {
    /// Key exchange message
    KeyExchange,
    /// Signature/authentication message
    Signature,
    /// Data transfer message
    Data,
    /// Acknowledgment message
    Ack,
    /// Connection close message
    Close,
    /// Error message
    Error,
}

impl From<MessageType> for SerdeMessageType {
    fn from(mt: MessageType) -> Self {
        match mt {
            MessageType::KeyExchange => SerdeMessageType::KeyExchange,
            MessageType::Signature => SerdeMessageType::Signature,
            MessageType::Data => SerdeMessageType::Data,
            MessageType::Ack => SerdeMessageType::Ack,
            MessageType::Close => SerdeMessageType::Close,
            MessageType::Error => SerdeMessageType::Error,
        }
    }
}

impl From<SerdeMessageType> for MessageType {
    fn from(smt: SerdeMessageType) -> Self {
        match smt {
            SerdeMessageType::KeyExchange => MessageType::KeyExchange,
            SerdeMessageType::Signature => MessageType::Signature,
            SerdeMessageType::Data => MessageType::Data,
            SerdeMessageType::Ack => MessageType::Ack,
            SerdeMessageType::Close => MessageType::Close,
            SerdeMessageType::Error => MessageType::Error,
        }
    }
}

/// Serializable version of MessageHeader
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SerdeMessageHeader {
    /// Protocol version
    pub version: u8,
    /// Message type
    pub msg_type: SerdeMessageType,
    /// Sequence number
    pub seq_num: u32,
    /// Payload length
    pub payload_len: u32,
}

impl From<MessageHeader> for SerdeMessageHeader {
    fn from(header: MessageHeader) -> Self {
        Self {
            version: header.version,
            msg_type: header.msg_type.into(),
            seq_num: header.seq_num,
            payload_len: header.payload_len,
        }
    }
}

impl From<SerdeMessageHeader> for MessageHeader {
    fn from(header: SerdeMessageHeader) -> Self {
        Self {
            version: header.version,
            msg_type: header.msg_type.into(),
            seq_num: header.seq_num,
            payload_len: header.payload_len,
        }
    }
}

/// Serializable version of SessionState
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SerdeSessionState {
    /// Session is new, no keys exchanged
    New,
    /// Key exchange initiated (client side)
    KeyExchangeInitiated,
    /// Key exchange completed (server side after receiving client public key)
    KeyExchangeCompleted,
    /// Authentication initiated (verification keys exchanged)
    AuthenticationInitiated,
    /// Authentication completed (signatures verified)
    AuthenticationCompleted,
    /// Session established and ready for data transfer
    Established,
    /// Session closed
    Closed,
}

impl From<SessionState> for SerdeSessionState {
    fn from(state: SessionState) -> Self {
        match state {
            SessionState::New => SerdeSessionState::New,
            SessionState::KeyExchangeInitiated => SerdeSessionState::KeyExchangeInitiated,
            SessionState::KeyExchangeCompleted => SerdeSessionState::KeyExchangeCompleted,
            SessionState::AuthenticationInitiated => SerdeSessionState::AuthenticationInitiated,
            SessionState::AuthenticationCompleted => SerdeSessionState::AuthenticationCompleted,
            SessionState::Established => SerdeSessionState::Established,
            SessionState::Closed => SerdeSessionState::Closed,
        }
    }
}

impl From<SerdeSessionState> for SessionState {
    fn from(state: SerdeSessionState) -> Self {
        match state {
            SerdeSessionState::New => SessionState::New,
            SerdeSessionState::KeyExchangeInitiated => SessionState::KeyExchangeInitiated,
            SerdeSessionState::KeyExchangeCompleted => SessionState::KeyExchangeCompleted,
            SerdeSessionState::AuthenticationInitiated => SessionState::AuthenticationInitiated,
            SerdeSessionState::AuthenticationCompleted => SessionState::AuthenticationCompleted,
            SerdeSessionState::Established => SessionState::Established,
            SerdeSessionState::Closed => SessionState::Closed,
        }
    }
}

/// A message wrapper for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeMessage {
    /// Message header
    pub header: SerdeMessageHeader,
    /// Message payload (encrypted data)
    pub payload: Vec<u8>,
    /// Message signature (if any)
    pub signature: Option<Vec<u8>>,
}

/// Session statistics for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeSessionStats {
    /// Session state
    pub state: SerdeSessionState,
    /// Number of messages sent
    pub messages_sent: u32,
    /// Number of messages received
    pub messages_received: u32,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Session creation time (Unix timestamp)
    pub created_at: u64,
    /// Last activity time (Unix timestamp)
    pub last_activity: u64,
}

/// Session configuration for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeSessionConfig {
    /// Protocol version
    pub version: u8,
    /// Maximum chunk size for streaming
    pub max_chunk_size: usize,
    /// Custom parameters
    pub parameters: HashMap<String, String>,
}

/// Serializes a message to JSON
#[cfg(feature = "serde_json")]
pub fn serialize_to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| crate::error::Error::Internal(format!("JSON serialization error: {}", e)))
}

/// Deserializes a message from JSON
#[cfg(feature = "serde_json")]
pub fn deserialize_from_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| crate::error::Error::Internal(format!("JSON deserialization error: {}", e)))
}

/// Serializes a message to binary using bincode
#[cfg(feature = "bincode")]
pub fn serialize_to_binary<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| crate::error::Error::Internal(format!("Bincode serialization error: {}", e)))
}

/// Deserializes a message from binary using bincode
#[cfg(feature = "bincode")]
pub fn deserialize_from_binary<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    bincode::deserialize(data).map_err(|e| crate::error::Error::Internal(format!("Bincode deserialization error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VERSION;
    
    #[cfg(feature = "serde_json")]
    #[test]
    fn test_message_header_json_serialization() {
        let header = MessageHeader::new(MessageType::Data, 42, 100);
        let serde_header: SerdeMessageHeader = header.into();
        
        let json = serialize_to_json(&serde_header).unwrap();
        let deserialized: SerdeMessageHeader = deserialize_from_json(&json).unwrap();
        let restored_header: MessageHeader = deserialized.into();
        
        assert_eq!(restored_header.version, VERSION);
        assert_eq!(restored_header.msg_type, MessageType::Data);
        assert_eq!(restored_header.seq_num, 42);
        assert_eq!(restored_header.payload_len, 100);
    }
    
    #[cfg(feature = "bincode")]
    #[test]
    fn test_message_header_binary_serialization() {
        let header = MessageHeader::new(MessageType::Data, 42, 100);
        let serde_header: SerdeMessageHeader = header.into();
        
        let binary = serialize_to_binary(&serde_header).unwrap();
        let deserialized: SerdeMessageHeader = deserialize_from_binary(&binary).unwrap();
        let restored_header: MessageHeader = deserialized.into();
        
        assert_eq!(restored_header.version, VERSION);
        assert_eq!(restored_header.msg_type, MessageType::Data);
        assert_eq!(restored_header.seq_num, 42);
        assert_eq!(restored_header.payload_len, 100);
    }
    
    #[cfg(feature = "serde_json")]
    #[test]
    fn test_session_state_json_serialization() {
        let state = SessionState::Established;
        let serde_state: SerdeSessionState = state.into();
        
        let json = serialize_to_json(&serde_state).unwrap();
        let deserialized: SerdeSessionState = deserialize_from_json(&json).unwrap();
        let restored_state: SessionState = deserialized.into();
        
        assert_eq!(restored_state, SessionState::Established);
    }
    
    #[cfg(feature = "serde_json")]
    #[test]
    fn test_message_json_serialization() {
        let header = MessageHeader::new(MessageType::Data, 42, 100);
        let payload = vec![1, 2, 3, 4];
        let signature = vec![5, 6, 7, 8];
        
        let message = SerdeMessage {
            header: header.into(),
            payload: payload.clone(),
            signature: Some(signature.clone()),
        };
        
        let json = serialize_to_json(&message).unwrap();
        let deserialized: SerdeMessage = deserialize_from_json(&json).unwrap();
        
        assert_eq!(deserialized.payload, payload);
        assert_eq!(deserialized.signature.unwrap(), signature);
        
        let restored_header: MessageHeader = deserialized.header.into();
        assert_eq!(restored_header.msg_type, MessageType::Data);
    }
}