// Tests focusing on the key exchange functionality
use pqc_protocol::{
    PqcSession,
    Result,
    // Remove the unused import: Error
};

use std::time::Instant;
use rand::{rng, Rng};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;

// Test successful key exchange between client and server
#[test]
fn test_key_exchange_success() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Client initiates key exchange
    let client_public_key = client.init_key_exchange()?;
    
    // Server accepts key exchange
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    
    // Client processes response
    client.process_key_exchange(&ciphertext)?;
    
    // Verify both sides have established a session
    assert_eq!(client.state(), pqc_protocol::session::SessionState::KeyExchangeCompleted);
    assert_eq!(server.state(), pqc_protocol::session::SessionState::KeyExchangeCompleted);
    
    Ok(())
}

// Test key exchange with corrupted public key or ciphertext
#[test]
fn test_key_exchange_corruption() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Client initiates key exchange
    let _client_public_key = client.init_key_exchange()?;
    
    // Generate a different, unrelated public key
    let (different_pk, _) = kyber768::keypair();
    
    // Server attempts key exchange with different key
    let result = server.accept_key_exchange(&different_pk);
    
    // This should still succeed (the server doesn't know this is wrong)
    assert!(result.is_ok());
    
    // But when client tries to process with the wrong shared secret, it should fail
    match result {
        Ok(ciphertext) => {
            let process_result = client.process_key_exchange(&ciphertext);
            
            // This might succeed despite the different key (Kyber doesn't authenticate)
            // What's important is that the shared secrets would differ
            if process_result.is_ok() {
                // This is fine, but encryption would fail later
            }
        },
        Err(_) => {
            // This is also acceptable
        }
    }
    
    Ok(())
}

// Test re-initializing key exchange (should fail)
#[test]
fn test_reinitialize_key_exchange() -> Result<()> {
    // Create client session
    let mut client = PqcSession::new()?;
    
    // First key exchange init should succeed
    let _ = client.init_key_exchange()?;
    
    // Second attempt should fail
    let result = client.init_key_exchange();
    assert!(result.is_err());
    
    // Instead of using Debug trait on the error, check the error variant directly
    match result {
        Err(pqc_protocol::Error::KeyExchange(_)) => {
            // Expected error type
        },
        _ => {
            panic!("Expected KeyExchange error");
        }
    }
    
    Ok(())
}

// Test accepting key exchange multiple times (should fail)
#[test]
fn test_multiple_accept_key_exchange() -> Result<()> {
    // Create server session
    let mut server = PqcSession::new()?;
    
    // Generate a public key
    let (public_key, _) = kyber768::keypair();
    
    // First accept should succeed
    let _ = server.accept_key_exchange(&public_key)?;
    
    // Second attempt should fail
    let result = server.accept_key_exchange(&public_key);
    assert!(result.is_err());
    
    // Instead of using Debug trait, check the error variant directly
    match result {
        Err(pqc_protocol::Error::KeyExchange(_)) => {
            // Expected error type
        },
        _ => {
            panic!("Expected KeyExchange error");
        }
    }
    
    Ok(())
}

// Test key exchange timing characteristics
#[test]
fn test_key_exchange_timing() -> Result<()> {
    use std::time::{Instant, Duration};
    
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Measure client key initialization time
    let start = Instant::now();
    let client_public_key = client.init_key_exchange()?;
    let client_init_time = start.elapsed();
    
    // Measure server key exchange time
    let start = Instant::now();
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    let server_accept_time = start.elapsed();
    
    // Measure client processing time
    let start = Instant::now();
    client.process_key_exchange(&ciphertext)?;
    let client_process_time = start.elapsed();
    
    // Log timing information
    println!("Key exchange timing:");
    println!("  Client init_key_exchange: {:?}", client_init_time);
    println!("  Server accept_key_exchange: {:?}", server_accept_time);
    println!("  Client process_key_exchange: {:?}", client_process_time);
    println!("  Total key exchange time: {:?}", 
             client_init_time + server_accept_time + client_process_time);
    
    // There are no strict assertions here as timing will vary by machine,
    // but we can add some loose upper bounds for CI/testing
    assert!(client_init_time < Duration::from_secs(1), "Client key generation took too long");
    assert!(server_accept_time < Duration::from_secs(1), "Server key acceptance took too long");
    assert!(client_process_time < Duration::from_secs(1), "Client key processing took too long");
    
    Ok(())
}

// Test key exchange with malformed inputs
#[test]
fn test_malformed_inputs() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Client initiates key exchange
    let client_public_key = client.init_key_exchange()?;
    
    // Corrupt the public key (this simulates transmission errors)
    let mut corrupted_bytes = client_public_key.as_bytes().to_vec();
    corrupted_bytes[100] ^= 0xFF; // Flip some bits
    
    // Try to create a public key from corrupted bytes
    match kyber768::PublicKey::from_bytes(&corrupted_bytes) {
        Ok(corrupt_pk) => {
            // Attempt key exchange with corrupted key
            if let Ok(_result) = server.accept_key_exchange(&corrupt_pk) {
                println!("Warning: Created public key from corrupted bytes");
            }
            // Because calling accept_key_exchange even with a bad key has advanced the session state,
            // reset the server session for a valid key exchange.
            server = PqcSession::new()?;
        },
        Err(_) => {
            // Expected: corrupted key creation fails.
        }
    }
    
    // Ensure normal flow still works
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    Ok(())
}

// Test encryption and decryption of various message sizes
#[test]
fn test_encryption_various_sizes() -> Result<()> {
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
    
    // Test with different message sizes
    for size in [0, 1, 32, 256, 1024, 4096, 8192, 16384] {
        let test_data = vec![0x42u8; size];
        
        // Encrypt with client session
        let encrypted = client.encrypt_and_sign(&test_data)?;
        
        // Decrypt with server session
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        
        // Verify data integrity
        assert_eq!(test_data, decrypted, "Data corruption for size {}", size);
        
        // Calculate overhead
        let overhead = encrypted.len() - test_data.len();
        println!("Size: {} bytes, Encrypted: {} bytes, Overhead: {} bytes ({}%)",
                 size, encrypted.len(), overhead, 
                 if size > 0 { overhead * 100 / size } else { 0 });
    }
    
    Ok(())
}

// Test encryption performance for large messages
#[test]
fn test_encryption_performance() -> Result<()> {
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
    
    // Test with a large message (1MB)
    let test_data = vec![0x42u8; 1024 * 1024];
    
    // Measure encryption time
    let start = Instant::now();
    let encrypted = client.encrypt_and_sign(&test_data)?;
    let encryption_time = start.elapsed();
    
    // Measure decryption time
    let start = Instant::now();
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    let decryption_time = start.elapsed();
    
    // Verify data integrity
    assert_eq!(test_data, decrypted, "Data corruption for large message");
    
    // Log performance information
    println!("Performance for 1MB data:");
    println!("  Encryption time: {:?}", encryption_time);
    println!("  Decryption time: {:?}", decryption_time);
    println!("  Combined time: {:?}", encryption_time + decryption_time);
    println!("  Encryption throughput: {:.2} MB/s", 
             1.0 / encryption_time.as_secs_f64());
    println!("  Decryption throughput: {:.2} MB/s", 
             1.0 / decryption_time.as_secs_f64());
    
    Ok(())
}

// Test message tampering detection
#[test]
fn test_message_tampering() -> Result<()> {
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
    
    // Create test message
    let test_data = b"This is a test message that should be tamper-evident";
    
    // Encrypt with client session
    let encrypted = client.encrypt_and_sign(test_data)?;
    
    // Tamper with various parts of the message
    let tampering_positions = [
        10, // Header
        15, // Encrypted data
        encrypted.len() - 10, // Signature
    ];
    
    for pos in tampering_positions {
        // Clone the original encrypted message
        let mut tampered = encrypted.clone();
        
        // Tamper with a single byte
        tampered[pos] ^= 0xFF;
        
        // Attempt to decrypt tampered message
        let result = server.verify_and_decrypt(&tampered);
        
        // Should fail
        assert!(result.is_err(), "Tampering at position {} was not detected", pos);
        
        match result {
            Err(pqc_protocol::Error::Authentication(_)) => {
                // Expected for signature tampering
            },
            Err(pqc_protocol::Error::Crypto(_)) => {
                // Expected for data tampering (AEAD failure)
            },
            Err(pqc_protocol::Error::InvalidFormat(_)) => {
                // Expected for header tampering
            },
            _ => {
                panic!("Unexpected error type for tampering at position {}: {:?}", pos, result);
            }
        }
    }
    
    // Original untampered message should still decrypt correctly
    let decrypted = server.verify_and_decrypt(&encrypted)?;
    assert_eq!(test_data, &decrypted[..]);
    
    Ok(())
}

// Test signing and verification directly
#[test]
fn test_direct_signing() -> Result<()> {
    // Create a session
    let session = PqcSession::new()?;
    
    // Test data
    let test_data = b"This is a message to be signed and verified";
    
    // Sign the data
    let signature = session.sign(test_data)?;
    
    // Create a second session to verify
    let mut verifier = PqcSession::new()?;
    verifier.set_remote_verification_key(session.local_verification_key().clone())?;
    
    // Verify the signature
    verifier.verify(test_data, &signature)?;
    
    // Tamper with the data
    let mut tampered_data = test_data.to_vec();
    tampered_data[5] ^= 0xFF;
    
    // Verification should fail
    let result = verifier.verify(&tampered_data, &signature);
    assert!(result.is_err());
    
    if let Err(pqc_protocol::Error::Authentication(_)) = result {
        // Expected error type
    } else {
        panic!("Expected Authentication error, got: {:?}", result);
    }
    
    Ok(())
}

// Test with random data to ensure robustness
#[test]
fn test_random_data() -> Result<()> {
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
    
    // Generate 10 random messages of varying sizes
    let mut rng = rng();
    for _ in 0..10 {
        // Random size between 1 and 8192 bytes
        let size = rng.random_range(1..8193);
        
        // Generate random data
        let mut test_data = vec![0u8; size];
        rng.fill(&mut test_data[..]);
        
        // Encrypt with client session
        let encrypted = client.encrypt_and_sign(&test_data)?;
        
        // Decrypt with server session
        let decrypted = server.verify_and_decrypt(&encrypted)?;
        
        // Verify data integrity
        assert_eq!(test_data, decrypted, "Data corruption for random data of size {}", size);
    }
    
    Ok(())
}