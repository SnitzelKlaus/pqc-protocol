// Integration tests for the pqc_protocol library
use pqc_protocol::{
    PqcSession,
    PqcStreamSender,
    Result,
    Error,
};

use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as KemCiphertext},
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature},
};

// Test full protocol flow from key exchange to encrypted communication
#[test]
fn test_full_protocol_flow() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(pqc_protocol::session::Role::Server);

    // Step 1: Key Exchange
    println!("Testing key exchange...");
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    // Step 2: Authentication
    println!("Testing authentication...");
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    // Step 3: Data Exchange
    println!("Testing data exchange...");
    for test_size in [10, 100, 1000, 10000] {
        let test_data = vec![0x42u8; test_size];
        
        // Client -> Server
        let encrypted = client.encrypt_and_sign(&test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, decrypted, "Data integrity failed for size {}", test_size);
        
        // Server -> Client
        let encrypted = server.encrypt_and_sign(&test_data)?;
        let decrypted = client.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, decrypted, "Data integrity failed for size {}", test_size);
    }

    // Step 4: Streaming
    println!("Testing streaming...");
    let large_data = vec![0xABu8; 100 * 1024]; // 100KB
    let mut sender = PqcStreamSender::new(&mut client, Some(16384));
    
    // Collect all encrypted chunks
    let chunks: Vec<Vec<u8>> = sender.stream_data(&large_data).collect::<Result<Vec<Vec<u8>>>>()?;
    
    // Server receives and processes all chunks
    let mut received_data = Vec::new();
    for chunk in chunks {
        let decrypted = server.verify_and_decrypt(&chunk)?;
        received_data.extend_from_slice(&decrypted);
    }
    
    assert_eq!(large_data, received_data, "Streaming data integrity failed");

    // Step 5: Session Close
    println!("Testing session close...");
    let close_message = client.close();
    assert_eq!(close_message[1], pqc_protocol::MessageType::Close as u8, "Close message type incorrect");

    Ok(())
}

// Test error handling for invalid signatures
#[test]
fn test_invalid_signature() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Complete key exchange and authentication
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    // Create valid encrypted message
    let test_data = b"This is a test message";
    let mut encrypted = client.encrypt_and_sign(test_data)?;
    
    // Tamper with the signature (last few bytes)
    let sig_start = encrypted.len() - 10;
    encrypted[sig_start] ^= 0xFF; // Flip some bits
    
    // Attempt to decrypt tampered message
    let result = server.verify_and_decrypt(&encrypted);
    
    // Should fail with authentication error
    assert!(result.is_err(), "Tampered signature should be rejected");
    if let Err(pqc_protocol::Error::Authentication(_)) = result {
        // Expected error type
    } else {
        panic!("Expected Authentication error, got: {:?}", result);
    }
    
    Ok(())
}

// Test protocol sequence errors
#[test]
fn test_protocol_sequence_errors() {
    // Test: Can't process key exchange without initiating
    let mut client = PqcSession::new().unwrap();
    let (_, dummy_ciphertext) = kyber768::keypair();
    let result = client.process_key_exchange(&dummy_ciphertext);
    assert!(result.is_err());
    
    // Test: Can't set verification key before key exchange
    let mut client = PqcSession::new().unwrap();
    let (_, dummy_vk) = dilithium3::keypair();
    let result = client.set_remote_verification_key(dummy_vk);
    assert!(result.is_err());
    
    // Test: Can't complete authentication before setting verification key
    let mut client = PqcSession::new().unwrap();
    let client_public_key = client.init_key_exchange().unwrap();
    let mut server = PqcSession::new().unwrap();
    let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
    client.process_key_exchange(&ciphertext).unwrap();
    let result = client.complete_authentication();
    assert!(result.is_err());
    
    // Test: Can't encrypt before completing authentication
    let mut client = PqcSession::new().unwrap();
    let client_public_key = client.init_key_exchange().unwrap();
    let mut server = PqcSession::new().unwrap();
    let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
    client.process_key_exchange(&ciphertext).unwrap();
    client.set_remote_verification_key(server.local_verification_key().clone()).unwrap();
    // Not calling complete_authentication
    let result = client.encrypt_and_sign(b"test");
    assert!(result.is_err());
}

// Test replay attack mitigation
#[test]
fn test_replay_protection() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Complete key exchange and authentication
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    // Send and successfully decrypt a message
    let test_data = b"First message";
    let encrypted = client.encrypt_and_sign(test_data)?;
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    assert_eq!(test_data, &decrypted[..]);
    
    // Try to "replay" the same encrypted message
    let result = server.verify_and_decrypt(&encrypted);
    
    // Should fail with sequence error
    assert!(result.is_err(), "Replayed message should be rejected");
    if let Err(pqc_protocol::Error::InvalidSequence) = result {
        // Expected error type
    } else {
        panic!("Expected InvalidSequence error, got: {:?}", result);
    }
    
    Ok(())
}

// Test with different chunk sizes for streaming
#[test]
fn test_streaming_chunk_sizes() -> Result<()> {
    let test_data = vec![0x42u8; 100 * 1024]; // 100KB
    
    for chunk_size in [1024, 4096, 8192, 16384, 32768] {
        // Create client and server sessions
        let mut client = PqcSession::new()?;
        let mut server = PqcSession::new()?;
        
        // Complete key exchange and authentication
        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;
        
        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;
        
        // Stream with specific chunk size
        let mut sender = PqcStreamSender::new(&mut client, Some(chunk_size));
        
        // Count chunks
        let chunks: Vec<Vec<u8>> = sender.stream_data(&test_data).collect::<Result<Vec<Vec<u8>>>>()?;
        
        // Expected number of chunks (ceiling division)
        let expected_chunks = (test_data.len() + chunk_size - 1) / chunk_size;
        assert_eq!(chunks.len(), expected_chunks, 
                   "Unexpected chunk count for size {}", chunk_size);
        
        // Verify data integrity
        let mut received_data = Vec::new();
        for chunk in chunks {
            let decrypted = server.verify_and_decrypt(&chunk)?;
            received_data.extend_from_slice(&decrypted);
        }
        
        assert_eq!(test_data, received_data, 
                   "Data integrity failed for chunk size {}", chunk_size);
    }
    
    Ok(())
}