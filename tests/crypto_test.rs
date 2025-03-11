use pqc_protocol::{
    PqcSession,
    Result,
    Error,
};
use std::time::Instant;
use rand::{rng, Rng};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;

// ----- Key Exchange Tests -----

#[test]
fn test_key_exchange_success() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    assert_eq!(client.state(), pqc_protocol::session::SessionState::KeyExchangeCompleted);
    assert_eq!(server.state(), pqc_protocol::session::SessionState::KeyExchangeCompleted);
    Ok(())
}

#[test]
fn test_key_exchange_corruption() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let _ = client.init_key_exchange()?;
    // Generate a different key
    let (different_pk, _) = kyber768::keypair();

    let result = server.accept_key_exchange(&different_pk);
    assert!(result.is_ok(), "Server should accept a key even if unrelated");

    // Processing with the wrong shared secret should lead to failure later.
    if let Ok(ciphertext) = result {
        let process_result = client.process_key_exchange(&ciphertext);
        if process_result.is_ok() {
            // Even if this passes, encryption would likely fail later.
            println!("Warning: processed a corrupted key exchange (shared secrets differ)");
        }
    }
    Ok(())
}

#[test]
fn test_reinitialize_key_exchange() -> Result<()> {
    let mut client = PqcSession::new()?;
    let _ = client.init_key_exchange()?;
    let result = client.init_key_exchange();
    assert!(result.is_err());
    match result {
        Err(Error::KeyExchange(_)) => {},
        _ => panic!("Expected KeyExchange error"),
    }
    Ok(())
}

#[test]
fn test_multiple_accept_key_exchange() -> Result<()> {
    let mut server = PqcSession::new()?;
    let (public_key, _) = kyber768::keypair();
    let _ = server.accept_key_exchange(&public_key)?;
    let result = server.accept_key_exchange(&public_key);
    assert!(result.is_err());
    match result {
        Err(Error::KeyExchange(_)) => {},
        _ => panic!("Expected KeyExchange error"),
    }
    Ok(())
}

#[test]
fn test_key_exchange_timing() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let start = Instant::now();
    let client_public_key = client.init_key_exchange()?;
    let client_init_time = start.elapsed();

    let start = Instant::now();
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    let server_accept_time = start.elapsed();

    let start = Instant::now();
    client.process_key_exchange(&ciphertext)?;
    let client_process_time = start.elapsed();

    println!("Key exchange timing:");
    println!("  Client init_key_exchange: {:?}", client_init_time);
    println!("  Server accept_key_exchange: {:?}", server_accept_time);
    println!("  Client process_key_exchange: {:?}", client_process_time);
    println!("  Total key exchange time: {:?}", client_init_time + server_accept_time + client_process_time);

    assert!(client_init_time < std::time::Duration::from_secs(1));
    assert!(server_accept_time < std::time::Duration::from_secs(1));
    assert!(client_process_time < std::time::Duration::from_secs(1));
    Ok(())
}

#[test]
fn test_malformed_inputs() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;

    let mut corrupted_bytes = client_public_key.as_bytes().to_vec();
    corrupted_bytes[100] ^= 0xFF; // simulate corruption

    // Try to create a public key from corrupted bytes.
    match kyber768::PublicKey::from_bytes(&corrupted_bytes) {
        Ok(corrupt_pk) => {
            if let Ok(_) = server.accept_key_exchange(&corrupt_pk) {
                println!("Warning: Created public key from corrupted bytes");
            }
            // Reset the server session to allow a valid exchange.
            server = PqcSession::new()?;
        },
        Err(_) => {
            // Expected failure to create a key.
        }
    }

    // Proceed with a normal exchange.
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    Ok(())
}

// ----- Encryption, Signing, and Tampering Tests -----

#[test]
fn test_encryption_various_sizes() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    // Key exchange and authentication.
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    for size in [0, 1, 32, 256, 1024, 4096, 8192, 16384] {
        let test_data = vec![0x42u8; size];
        let encrypted = client.encrypt_and_sign(&test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, decrypted, "Data corruption for size {}", size);
        let overhead = encrypted.len() - test_data.len();
        println!("Size: {} bytes, Encrypted: {} bytes, Overhead: {} bytes ({}%)",
                 size, encrypted.len(), overhead,
                 if size > 0 { overhead * 100 / size } else { 0 });
    }
    Ok(())
}

#[test]
fn test_encryption_performance() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    let test_data = vec![0x42u8; 1024 * 1024];

    let start = Instant::now();
    let encrypted = client.encrypt_and_sign(&test_data)?;
    let encryption_time = start.elapsed();

    let start = Instant::now();
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    let decryption_time = start.elapsed();

    assert_eq!(test_data, decrypted, "Data corruption for large message");

    println!("Performance for 1MB data:");
    println!("  Encryption time: {:?}", encryption_time);
    println!("  Decryption time: {:?}", decryption_time);
    println!("  Combined time: {:?}", encryption_time + decryption_time);
    println!("  Encryption throughput: {:.2} MB/s", 1.0 / encryption_time.as_secs_f64());
    println!("  Decryption throughput: {:.2} MB/s", 1.0 / decryption_time.as_secs_f64());

    Ok(())
}

#[test]
fn test_message_tampering() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    let test_data = b"This is a test message that should be tamper-evident";
    let encrypted = client.encrypt_and_sign(test_data)?;

    let tampering_positions = [10, 15, encrypted.len() - 10];
    for pos in tampering_positions.iter() {
        let mut tampered = encrypted.clone();
        tampered[*pos] ^= 0xFF;
        let result = server.verify_and_decrypt(&tampered);
        assert!(result.is_err(), "Tampering at position {} was not detected", pos);
        match result {
            Err(Error::Authentication(_)) | Err(Error::Crypto(_)) | Err(Error::InvalidFormat(_)) => {},
            _ => panic!("Unexpected error type for tampering at position {}: {:?}", pos, result),
        }
    }
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    assert_eq!(test_data, &decrypted[..]);
    Ok(())
}

#[test]
fn test_direct_signing() -> Result<()> {
    let mut signer = PqcSession::new()?;
    let mut verifier = PqcSession::new()?;
    // Set verifier as server.
    verifier.set_role(pqc_protocol::session::Role::Server);

    let signer_public_key = signer.init_key_exchange()?;
    let ciphertext = verifier.accept_key_exchange(&signer_public_key)?;
    signer.process_key_exchange(&ciphertext)?;

    signer.set_remote_verification_key(verifier.local_verification_key().clone())?;
    verifier.set_remote_verification_key(signer.local_verification_key().clone())?;
    signer.complete_authentication()?;
    verifier.complete_authentication()?;

    let test_data = b"This is a message to be signed and verified";
    let signature = signer.sign(test_data)?;
    verifier.verify(test_data, &signature)?;

    let mut tampered_data = test_data.to_vec();
    tampered_data[5] ^= 0xFF;
    let result = verifier.verify(&tampered_data, &signature);
    assert!(result.is_err());
    match result {
        Err(Error::Authentication(_)) => {},
        _ => panic!("Expected Authentication error, got: {:?}", result),
    }
    Ok(())
}

#[test]
fn test_random_data() -> Result<()> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;

    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;

    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    client.complete_authentication()?;
    server.complete_authentication()?;

    let mut rng = rng();
    for _ in 0..10 {
        let size = rng.random_range(1..8193);
        let mut test_data = vec![0u8; size];
        rng.fill(&mut test_data[..]);
        let encrypted = client.encrypt_and_sign(&test_data)?;
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        assert_eq!(test_data, decrypted, "Data corruption for random data of size {}", size);
    }
    Ok(())
}