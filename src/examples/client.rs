use pqc_protocol::{PqcSession, PqcStreamSender, Result};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use pqcrypto_traits::kem::{PublicKey, Ciphertext};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;

fn main() -> Result<()> {
    println!("PQC Protocol Client Example");
    println!("===========================");
    
    // Connect to server
    println!("Connecting to server...");
    let mut stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to server");
    
    // Create session
    let mut session = PqcSession::new()?;
    
    // Initialize key exchange
    println!("Initiating key exchange...");
    let client_public_key = session.init_key_exchange()?;
    
    // Send public key to server
    let pk_bytes = client_public_key.as_bytes();
    stream.write_all(&(pk_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(pk_bytes)?;
    
    // Receive ciphertext from server
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let ciphertext_len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut ciphertext_bytes = vec![0u8; ciphertext_len];
    stream.read_exact(&mut ciphertext_bytes)?;
    
    // Convert to Kyber ciphertext
    let ciphertext = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&ciphertext_bytes)
        .expect("Invalid ciphertext received");
    
    // Process key exchange
    println!("Processing key exchange response...");
    session.process_key_exchange(&ciphertext)?;
    
    // Send local verification key
    println!("Exchanging verification keys...");
    let vk_bytes = session.local_verification_key().as_bytes();
    stream.write_all(&(vk_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(vk_bytes)?;
    
    // Receive server verification key
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let server_vk_len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut server_vk_bytes = vec![0u8; server_vk_len];
    stream.read_exact(&mut server_vk_bytes)?;
    
    // Convert to Dilithium verification key
    let server_vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&server_vk_bytes)
        .expect("Invalid verification key received");
    
    // Set remote verification key and complete authentication
    session.set_remote_verification_key(server_vk)?;
    session.complete_authentication()?;
    
    println!("Secure connection established!");
    
    // Example data to send
    let data = b"Hello, post-quantum world! This is a secret message.";
    println!("Sending encrypted message: {:?}", String::from_utf8_lossy(data));
    
    // Encrypt and send
    let encrypted = session.encrypt_and_sign(data)?;
    stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
    stream.write_all(&encrypted)?;
    
    // Receive response
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let response_len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;
    
    // Decrypt and verify
    let decrypted = session.verify_and_decrypt(&response)?;
    println!("Received response: {:?}", String::from_utf8_lossy(&decrypted));
    
    // Demonstrate streaming large data
    println!("\nDemonstrating large data streaming...");
    let large_data = vec![0x42u8; 1_000_000]; // 1MB of data
    
    let mut sender = PqcStreamSender::new(&mut session, Some(16384));
    let mut total_sent = 0;
    
    println!("Streaming 1MB of data in chunks...");
    for (i, chunk_result) in sender.stream_data(&large_data).enumerate() {
        let chunk = chunk_result?;
        
        // Send chunk
        stream.write_all(&(chunk.len() as u32).to_be_bytes())?;
        stream.write_all(&chunk)?;
        total_sent += 1;
        
        if i % 10 == 0 {
            print!(".");
            io::stdout().flush()?;
        }
    }
    println!("\nSent {} chunks ({} bytes total)", total_sent, large_data.len());
    
    // Close session
    println!("Closing session...");
    let close_msg = session.close();
    stream.write_all(&(close_msg.len() as u32).to_be_bytes())?;
    stream.write_all(&close_msg)?;
    
    println!("Session closed successfully");
    Ok(())
}