// Tests focusing on cryptographic operations
use pqc_protocol::{
    PqcSession,
    Result,
    Error,
};

use std::time::Instant;
use rand::{thread_rng, Rng};

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
    let mut encrypted = client.encrypt_and_sign(test_data)?;
    
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
    let mut rng = thread_rng();
    for _ in 0..10 {
        // Random size between 1 and 8192 bytes
        let size = rng.gen_range(1..8193);
        
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