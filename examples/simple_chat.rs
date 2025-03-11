/*!
A simple chat example using the PQC Protocol.

This example demonstrates how to use the high-level API to create
a simple chat application between a client and server.
*/

use pqc_protocol::{
    api::{PqcClient, PqcServer},
    Result,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

const SERVER_ADDR: &str = "127.0.0.1:8090";

/// Run the client side of the chat
fn run_client() -> Result<()> {
    println!("Connecting to server at {}...", SERVER_ADDR);
    let mut stream = TcpStream::connect(SERVER_ADDR)?;
    let mut client = PqcClient::new()?;
    
    // Key exchange and authentication
    println!("Initiating secure connection...");
    
    // Step 1: Send public key
    let public_key = client.connect()?;
    stream.write_all(&(public_key.len() as u32).to_be_bytes())?;
    stream.write_all(&public_key)?;
    
    // Step 2: Receive server's ciphertext and verification key
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let ct_len = u32::from_be_bytes(len_buf);
    
    let mut ciphertext = vec![0u8; ct_len as usize];
    stream.read_exact(&mut ciphertext)?;
    
    stream.read_exact(&mut len_buf)?;
    let vk_len = u32::from_be_bytes(len_buf);
    
    let mut server_vk = vec![0u8; vk_len as usize];
    stream.read_exact(&mut server_vk)?;
    
    // Step 3: Process response and send our verification key
    let client_vk = client.process_response(&ciphertext)?;
    stream.write_all(&(client_vk.len() as u32).to_be_bytes())?;
    stream.write_all(&client_vk)?;
    
    // Step 4: Complete authentication
    client.authenticate(&server_vk)?;
    
    println!("Secure connection established!");
    
    // Chat loop
    let mut input = String::new();
    
    // Non-blocking read for receiving messages
    stream.set_nonblocking(true)?;
    
    loop {
        // Check for incoming messages
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {
                let msg_len = u32::from_be_bytes(len_buf);
                let mut message = vec![0u8; msg_len as usize];
                stream.read_exact(&mut message)?;
                
                let decrypted = client.receive(&message)?;
                let text = String::from_utf8_lossy(&decrypted);
                println!("Server: {}", text);
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available yet, that's fine
            },
            Err(e) => {
                return Err(e.into());
            }
        }
        
        // Send message if user has input
        if io::stdin().read_line(&mut input)? > 0 {
            let input = input.trim();
            
            if input == "/quit" {
                println!("Closing connection...");
                let close_msg = client.close();
                stream.write_all(&(close_msg.len() as u32).to_be_bytes())?;
                stream.write_all(&close_msg)?;
                break;
            }
            
            let encrypted = client.send(input.as_bytes())?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
            
            input.clear();
        }
        
        // Small sleep to prevent high CPU usage
        thread::sleep(Duration::from_millis(100));
    }
    
    Ok(())
}

/// Run the server side of the chat
fn run_server() -> Result<()> {
    println!("Starting server on {}...", SERVER_ADDR);
    let listener = TcpListener::bind(SERVER_ADDR)?;
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connected: {}", stream.peer_addr()?);
                handle_client(stream)?;
            },
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}

/// Handle a client connection
fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut server = PqcServer::new()?;
    
    // Key exchange and authentication
    println!("Performing key exchange...");
    
    // Step 1: Receive client's public key
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let pk_len = u32::from_be_bytes(len_buf);
    
    let mut client_pk = vec![0u8; pk_len as usize];
    stream.read_exact(&mut client_pk)?;
    
    // Step 2: Process client's public key and send ciphertext and verification key
    let (ciphertext, server_vk) = server.accept(&client_pk)?;
    
    stream.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
    stream.write_all(&ciphertext)?;
    
    stream.write_all(&(server_vk.len() as u32).to_be_bytes())?;
    stream.write_all(&server_vk)?;
    
    // Step 3: Receive client's verification key
    stream.read_exact(&mut len_buf)?;
    let vk_len = u32::from_be_bytes(len_buf);
    
    let mut client_vk = vec![0u8; vk_len as usize];
    stream.read_exact(&mut client_vk)?;
    
    // Step 4: Complete authentication
    server.authenticate(&client_vk)?;
    
    println!("Secure connection established!");
    
    // Send welcome message
    let welcome = "Welcome to the PQC Protocol chat server! Type /quit to exit.";
    let encrypted = server.send(welcome.as_bytes())?;
    stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
    stream.write_all(&encrypted)?;
    
    // Chat loop
    let mut input = String::new();
    
    // Non-blocking read for receiving messages
    stream.set_nonblocking(true)?;
    
    loop {
        // Check for incoming messages
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {
                let msg_len = u32::from_be_bytes(len_buf);
                let mut message = vec![0u8; msg_len as usize];
                stream.read_exact(&mut message)?;
                
                // Check if it's a close message
                if message.len() > 1 && message[1] == 0x05 { // Close message type
                    println!("Client requested to close the connection");
                    break;
                }
                
                match server.receive(&message) {
                    Ok(decrypted) => {
                        let text = String::from_utf8_lossy(&decrypted);
                        println!("Client: {}", text);
                        
                        // Echo back the message
                        let response = format!("You said: {}", text);
                        let encrypted = server.send(response.as_bytes())?;
                        stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
                        stream.write_all(&encrypted)?;
                    },
                    Err(e) => {
                        eprintln!("Error decrypting message: {}", e);
                    }
                }
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No data available yet, that's fine
            },
            Err(e) => {
                return Err(e.into());
            }
        }
        
        // Send message if user has input
        if io::stdin().read_line(&mut input)? > 0 {
            let input = input.trim();
            
            if input == "/quit" {
                println!("Closing connection...");
                let close_msg = server.close();
                stream.write_all(&(close_msg.len() as u32).to_be_bytes())?;
                stream.write_all(&close_msg)?;
                break;
            }
            
            let encrypted = server.send(input.as_bytes())?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
            
            input.clear();
        }
        
        // Small sleep to prevent high CPU usage
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("Connection closed");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && args[1] == "--server" {
        run_server()
    } else {
        run_client()
    }
}