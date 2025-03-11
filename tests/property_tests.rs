use pqc_protocol::{
    session::{PqcSession, Role, SessionState},
    message::{MessageType, MessageHeader},
    error::Result,
};

use proptest::prelude::*;

// Strategy for generating valid sequence numbers
fn sequence_numbers() -> impl Strategy<Value = u32> {
    0..1000u32
}

// Strategy for generating message types
fn message_types() -> impl Strategy<Value = MessageType> {
    prop_oneof![
        Just(MessageType::KeyExchange),
        Just(MessageType::Signature),
        Just(MessageType::Data),
        Just(MessageType::Ack),
        Just(MessageType::Close),
        Just(MessageType::Error)
    ]
}

// Strategy for generating payload lengths
fn payload_lengths() -> impl Strategy<Value = u32> {
    0..10000u32
}

// Strategy for generating message headers
fn message_headers() -> impl Strategy<Value = MessageHeader> {
    (message_types(), sequence_numbers(), payload_lengths())
        .prop_map(|(msg_type, seq_num, payload_len)| {
            MessageHeader::new(msg_type, seq_num, payload_len)
        })
}

// Strategy for generating small data buffers
fn small_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..100)
}

// Strategy for generating medium data buffers
fn medium_data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 100..1000)
}

proptest! {
    #[test]
    fn test_header_serialization_roundtrip(header in message_headers()) {
        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).unwrap();
        prop_assert_eq!(header, parsed);
    }
    
    #[test]
    fn test_header_version_validation(header in message_headers()) {
        let mut bytes = header.to_bytes();
        bytes[0] = 0xFF; // Invalid version
        
        let result = MessageHeader::from_bytes(&bytes);
        prop_assert!(result.is_err());
        
        if let Err(pqc_protocol::error::Error::UnsupportedVersion(ver)) = result {
            prop_assert_eq!(ver, 0xFF);
        } else {
            prop_assert!(false, "Expected UnsupportedVersion error");
        }
    }
    
    #[test]
    fn test_header_message_type_validation(header in message_headers()) {
        let mut bytes = header.to_bytes();
        bytes[1] = 0x42; // Invalid message type
        
        let result = MessageHeader::from_bytes(&bytes);
        prop_assert!(result.is_err());
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip(data in small_data()) {
        let client_result = perform_encrypt_decrypt_roundtrip(data.clone());
        prop_assert!(client_result.is_ok());
        
        let decrypted = client_result.unwrap();
        prop_assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_message_tampering(data in medium_data()) {
        let (encrypted, mut client, mut server) = setup_encrypt_decrypt_session().unwrap();
        
        // Tamper with the encrypted data
        let mut tampered = encrypted.clone();
        if tampered.len() > 15 {
            tampered[15] ^= 0xFF;
            let result = server.verify_and_decrypt(&tampered);
            prop_assert!(result.is_err());
        }
    }
    
    #[test]
    fn test_sequence_number_validation(data in small_data()) {
        let (encrypted, mut client, mut server) = setup_encrypt_decrypt_session().unwrap();
        
        // First verification should work
        let result = server.verify_and_decrypt(&encrypted);
        prop_assert!(result.is_ok());
        
        // Second verification with the same message should fail (replay attack)
        let result = server.verify_and_decrypt(&encrypted);
        prop_assert!(result.is_err());
        
        if let Err(pqc_protocol::error::Error::InvalidSequence) = result {
            // Expected error
        } else {
            prop_assert!(false, "Expected InvalidSequence error");
        }
    }
}

// Helper function to set up a secure session for testing
fn setup_encrypt_decrypt_session() -> Result<(Vec<u8>, PqcSession, PqcSession)> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(Role::Server);
    
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    let data = b"Test data for encryption";
    let encrypted = client.encrypt_and_sign(data)?;
    
    Ok((encrypted, client, server))
}

// Helper function to perform a full encrypt/decrypt roundtrip
fn perform_encrypt_decrypt_roundtrip(data: Vec<u8>) -> Result<Vec<u8>> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(Role::Server);
    
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    let encrypted = client.encrypt_and_sign(&data)?;
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    
    Ok(decrypted)
}

// Additional property tests for streaming functionality
proptest! {
    #[test]
    fn test_stream_data_reconstruction(data in prop::collection::vec(any::<u8>(), 1000..5000)) {
        let result = perform_streaming_roundtrip(data.clone(), 256);
        prop_assert!(result.is_ok());
        
        let reconstructed = result.unwrap();
        prop_assert_eq!(data, reconstructed);
    }
    
    #[test]
    fn test_various_chunk_sizes(data in prop::collection::vec(any::<u8>(), 2000..3000)) {
        // Test with different chunk sizes
        for chunk_size in [128, 256, 512, 1024] {
            let result = perform_streaming_roundtrip(data.clone(), chunk_size);
            prop_assert!(result.is_ok());
            
            let reconstructed = result.unwrap();
            prop_assert_eq!(data, reconstructed);
        }
    }
    
    #[test]
    fn test_empty_chunks(chunk_size in 10..1000u32) {
        let data = Vec::new(); // Empty data
        let result = perform_streaming_roundtrip(data, chunk_size as usize);
        prop_assert!(result.is_ok());
        
        let reconstructed = result.unwrap();
        prop_assert!(reconstructed.is_empty());
    }
}

// Helper function to perform streaming data transfer with reconstruction
fn perform_streaming_roundtrip(data: Vec<u8>, chunk_size: usize) -> Result<Vec<u8>> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(Role::Server);
    
    // Setup secure session
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    // Stream data from client to server
    let mut sender = pqc_protocol::streaming::PqcStreamSender::new(&mut client, Some(chunk_size));
    
    // Collect all encrypted chunks
    let chunks: Vec<Vec<u8>> = sender.stream_data(&data).collect::<Result<Vec<Vec<u8>>>>()?;
    
    // Process each chunk and reconstruct original data
    let mut reconstructed = Vec::new();
    for chunk in chunks {
        let decrypted = server.verify_and_decrypt(&chunk)?;
        reconstructed.extend_from_slice(&decrypted);
    }
    
    Ok(reconstructed)
}

// Tests for session state transitions
proptest! {
    #[test]
    fn test_client_state_transitions() {
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        server.set_role(Role::Server);
        
        // Initial state
        prop_assert_eq!(client.state(), SessionState::New);
        
        // Key exchange initiated
        let client_public_key = client.init_key_exchange().unwrap();
        prop_assert_eq!(client.state(), SessionState::KeyExchangeInitiated);
        
        // Key exchange completed
        let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
        client.process_key_exchange(&ciphertext).unwrap();
        prop_assert_eq!(client.state(), SessionState::KeyExchangeCompleted);
        
        // Authentication initiated
        client.set_remote_verification_key(server.local_verification_key().clone()).unwrap();
        prop_assert_eq!(client.state(), SessionState::AuthenticationInitiated);
        
        // Authentication completed
        client.complete_authentication().unwrap();
        prop_assert_eq!(client.state(), SessionState::Established);
        
        // Session closed
        client.close();
        prop_assert_eq!(client.state(), SessionState::Closed);
    }
    
    #[test]
    fn test_server_state_transitions() {
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        server.set_role(Role::Server);
        
        // Initial state
        prop_assert_eq!(server.state(), SessionState::New);
        
        // Key exchange in progress
        let client_public_key = client.init_key_exchange().unwrap();
        
        // Key exchange completed
        server.accept_key_exchange(&client_public_key).unwrap();
        prop_assert_eq!(server.state(), SessionState::KeyExchangeCompleted);
        
        // Authentication initiated
        server.set_remote_verification_key(client.local_verification_key().clone()).unwrap();
        prop_assert_eq!(server.state(), SessionState::AuthenticationInitiated);
        
        // Authentication completed
        server.complete_authentication().unwrap();
        prop_assert_eq!(server.state(), SessionState::Established);
        
        // Session closed
        server.close();
        prop_assert_eq!(server.state(), SessionState::Closed);
    }
}

// Additional tests for error scenarios
proptest! {
    #[test]
    fn test_invalid_state_operations(data in small_data()) {
        // Test attempting to encrypt before establishing a session
        let mut session = PqcSession::new().unwrap();
        let result = session.encrypt_and_sign(&data);
        prop_assert!(result.is_err());
        
        // Test attempting to set verification key before key exchange
        let verification_key = session.local_verification_key().clone();
        let result = session.set_remote_verification_key(verification_key);
        prop_assert!(result.is_err());
        
        // Test attempting to complete authentication without setting verification key
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        server.set_role(Role::Server);
        
        let client_public_key = client.init_key_exchange().unwrap();
        let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
        client.process_key_exchange(&ciphertext).unwrap();
        
        // Try to complete authentication without setting verification key
        let result = client.complete_authentication();
        prop_assert!(result.is_err());
    }
}