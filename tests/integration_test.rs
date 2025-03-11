// tests/integration_tests.rs
use pqc_protocol::{
    PqcSession,
    PqcStreamSender,
    Result,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;

#[test]
fn test_full_protocol_flow() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(pqc_protocol::session::Role::Server);

    println!("Testing key exchange...");
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    println!("Testing authentication...");
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

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

    println!("Testing streaming...");
    let large_data = vec![0xABu8; 100 * 1024]; // 100KB
    let mut sender = PqcStreamSender::new(&mut client, Some(16384));
    let chunks: Vec<Vec<u8>> = sender.stream_data(&large_data).collect::<Result<Vec<Vec<u8>>>>()?;
    let mut received_data = Vec::new();
    for chunk in chunks {
        let decrypted = server.verify_and_decrypt(&chunk)?;
        received_data.extend_from_slice(&decrypted);
    }
    assert_eq!(large_data, received_data, "Streaming data integrity failed");

    println!("Testing session close...");
    let close_message = client.close();
    assert_eq!(close_message[1], pqc_protocol::MessageType::Close as u8, "Close message type incorrect");

    Ok(())
}

#[test]
fn test_invalid_signature() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    let test_data = b"This is a test message";
    let mut encrypted = client.encrypt_and_sign(test_data)?;

    let sig_start = encrypted.len() - 10;
    encrypted[sig_start] ^= 0xFF; // tamper with signature

    let result = server.verify_and_decrypt(&encrypted);
    assert!(result.is_err(), "Tampered signature should be rejected");
    match result {
        Err(pqc_protocol::Error::Authentication(_)) => {},
        _ => panic!("Expected Authentication error, got: {:?}", result),
    }
    Ok(())
}

#[test]
fn test_protocol_sequence_errors() {
    // Test processing key exchange without initialization.
    let mut client = PqcSession::new().unwrap();
    let (pk, _) = kyber768::keypair();
    let (_, ciphertext) = kyber768::encapsulate(&pk);
    let result = client.process_key_exchange(&ciphertext);
    assert!(result.is_err());

    // Test setting verification key before key exchange.
    let mut client = PqcSession::new().unwrap();
    let (dummy_vk, _) = dilithium3::keypair();
    let result = client.set_remote_verification_key(dummy_vk);
    assert!(result.is_err());

    // Test completing authentication before setting verification key.
    let mut client = PqcSession::new().unwrap();
    let client_public_key = client.init_key_exchange().unwrap();
    let mut server = PqcSession::new().unwrap();
    let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
    client.process_key_exchange(&ciphertext).unwrap();
    let result = client.complete_authentication();
    assert!(result.is_err());

    // Test encrypting before completing authentication.
    let mut client = PqcSession::new().unwrap();
    let client_public_key = client.init_key_exchange().unwrap();
    let mut server = PqcSession::new().unwrap();
    let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
    client.process_key_exchange(&ciphertext).unwrap();
    client.set_remote_verification_key(server.local_verification_key().clone()).unwrap();
    let result = client.encrypt_and_sign(b"test");
    assert!(result.is_err());
}

#[test]
fn test_replay_protection() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    let test_data = b"First message";
    let encrypted = client.encrypt_and_sign(test_data)?;
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    assert_eq!(test_data, &decrypted[..]);

    let result = server.verify_and_decrypt(&encrypted);
    assert!(result.is_err(), "Replayed message should be rejected");
    match result {
        Err(pqc_protocol::Error::InvalidSequence) => {},
        _ => panic!("Expected InvalidSequence error, got: {:?}", result),
    }
    Ok(())
}

#[test]
fn test_streaming_chunk_sizes() -> Result<()> {
    let test_data = vec![0x42u8; 100 * 1024]; // 100KB

    for chunk_size in [1024, 4096, 8192, 16384, 32768] {
        let mut client = PqcSession::new()?;
        let mut server = PqcSession::new()?;

        let client_public_key = client.init_key_exchange()?;
        let ciphertext = server.accept_key_exchange(&client_public_key)?;
        client.process_key_exchange(&ciphertext)?;

        client.set_remote_verification_key(server.local_verification_key().clone())?;
        server.set_remote_verification_key(client.local_verification_key().clone())?;
        client.complete_authentication()?;
        server.complete_authentication()?;

        let mut sender = PqcStreamSender::new(&mut client, Some(chunk_size));
        let chunks: Vec<Vec<u8>> = sender.stream_data(&test_data).collect::<Result<Vec<Vec<u8>>>>()?;
        let expected_chunks = (test_data.len() + chunk_size - 1) / chunk_size;
        assert_eq!(chunks.len(), expected_chunks, "Unexpected chunk count for size {}", chunk_size);

        let mut received_data = Vec::new();
        for chunk in chunks {
            let decrypted = server.verify_and_decrypt(&chunk)?;
            received_data.extend_from_slice(&decrypted);
        }
        assert_eq!(test_data, received_data, "Data integrity failed for chunk size {}", chunk_size);
    }
    Ok(())
}
