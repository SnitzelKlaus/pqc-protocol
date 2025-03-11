// TODO - Update to work with new project structure

use pqc_protocol::{PqcSession, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use pqcrypto_traits::kem::{PublicKey, Ciphertext};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;

fn handle_client(mut stream: TcpStream) -> Result<()> {
    println!("New client connected: {}", stream.peer_addr()?);
    
    // Create session
    let mut session = PqcSession::new()?;
    session.set_role(pqc_protocol::session::Role::Server);
    
    // Receive client's public key
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let pk_len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut pk_bytes = vec![0u8; pk_len];
    stream.read_exact(&mut pk_bytes)?;
    
    // Convert to Kyber public key
    let client_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&pk_bytes)
        .expect("Invalid public key received");
    
    // Accept key exchange
    println!("Accepting key exchange...");
    let ciphertext = session.accept_key_exchange(&client_pk)?;
    
    // Send ciphertext to client
    let ct_bytes = ciphertext.as_bytes();
    stream.write_all(&(ct_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(ct_bytes)?;
    
    // Receive client's verification key
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let vk_len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut vk_bytes = vec![0u8; vk_len];
    stream.read_exact(&mut vk_bytes)?;
    
    // Convert to Dilithium verification key
    let client_vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&vk_bytes)
        .expect("Invalid verification key received");
    
    // Set remote verification key
    session.set_remote_verification_key(client_vk)?;
    
    // Send server's verification key
    let server_vk_bytes = session.local_verification_key().as_bytes();
    stream.write_all(&(server_vk_bytes.len() as u32).to_be_bytes())?;
    stream.write_all(server_vk_bytes)?;
    
    // Complete authentication
    session.complete_authentication()?;
    
    println!("Secure connection established with client!");
    
    // Main communication loop
    let mut bytes_received = 0;
    let mut message_count = 0;
    
    loop {
        // Receive message length
        let mut len_bytes = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_bytes) {
            println!("Client disconnected: {}", e);
            break;
        }
        
        let msg_len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read message
        let mut message = vec![0u8; msg_len];
        stream.read_exact(&mut message)?;
        
        // Check if it's a close message
        if message.len() > 1 && message[1] == pqc_protocol::types::MessageType::Close as u8 {
            println!("Client requested to close the connection");
            break;
        }
        
        // Decrypt and verify
        let decrypted = match session.verify_and_decrypt(&message) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to decrypt message: {}", e);
                continue;
            }
        };
        
        bytes_received += decrypted.len();
        message_count += 1;
        
        if message_count == 1 {
            // For the first message, print and send a response
            println!("Received message: {:?}", String::from_utf8_lossy(&decrypted));
            
            // Send response
            let response = b"Hello from the server! Your message was received.";
            let encrypted = session.encrypt_and_sign(response)?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
        } else if message_count % 10 == 0 {
            // Just print progress for streaming data
            println!("Received {} messages ({} bytes total)", message_count, bytes_received);
        }
    }
    
    println!("Connection closed. Received {} messages ({} bytes total)", 
             message_count, bytes_received);
    Ok(())
}

fn main() -> Result<()> {
    println!("PQC Protocol Server Example");
    println!("===========================");
    
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Server listening on 127.0.0.1:8080");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream) {
                        println!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}