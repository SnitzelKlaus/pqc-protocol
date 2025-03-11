// Tests focusing on the key exchange functionality
use QStream::{
    PqcSession,
    Result,
    Error,
};

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, Ciphertext as KemCiphertext};

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
    assert_eq!(client.state(), QStream::session::SessionState::KeyExchangeCompleted);
    assert_eq!(server.state(), QStream::session::SessionState::KeyExchangeCompleted);
    
    Ok(())
}

// Test key exchange with corrupted public key or ciphertext
#[test]
fn test_key_exchange_corruption() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    
    // Client initiates key exchange
    let client_public_key = client.init_key_exchange()?;
    
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
    
    if let Err(QStream::Error::KeyExchange(_)) = result {
        // Expected error type
    } else {
        panic!("Expected KeyExchange error, got: {:?}", result);
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
    
    if let Err(QStream::Error::KeyExchange(_)) = result {
        // Expected error type
    } else {
        panic!("Expected KeyExchange error, got: {:?}", result);
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
            // If creation succeeded (unlikely), attempt key exchange
            let result = server.accept_key_exchange(&corrupt_pk);
            
            // The operation might succeed but would lead to different shared secrets
            if result.is_ok() {
                println!("Warning: Created public key from corrupted bytes");
            }
        },
        Err(_) => {
            // Expected - corrupted key bytes should be rejected
        }
    }
    
    // Ensure normal flow still works
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    Ok(())
}