/*!
Example of using the asynchronous PQC Protocol API to transfer a file.

This example demonstrates how to:
1. Establish a secure connection using the PQC protocol with async/await
2. Stream a file in chunks with encryption and authentication
3. Receive and reassemble the file asynchronously
*/

use pqc_protocol::async_api::{AsyncPqcClient, AsyncPqcServer, AsyncPqcReadExt, AsyncPqcWriteExt};
use pqc_protocol::error::Result;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    println!("PQC Protocol Async File Transfer Example");
    
    // Let's create a simple "connection" for demonstration
    // In a real application, these would be separate processes communicating over a network
    let client = AsyncPqcClient::new().await?;
    let server = AsyncPqcServer::new().await?;
    
    println!("Establishing secure connection...");
    
    // Step 1: Key Exchange
    // Client initiates the connection
    let client_pk = client.connect().await?;
    println!("Client initiated connection");
    
    // Server accepts the connection
    let (server_ct, server_vk) = server.accept(&client_pk).await?;
    println!("Server accepted connection");
    
    // Client processes the server's response
    let client_vk = client.process_response(&server_ct).await?;
    println!("Client processed server response");
    
    // Step 2: Authentication
    // Server authenticates the client
    server.authenticate(&client_vk).await?;
    println!("Server authenticated client");
    
    // Client authenticates the server
    client.authenticate(&server_vk).await?;
    println!("Client authenticated server");
    
    println!("Secure connection established!");
    
    // Step 3: File Transfer
    // For this example, we'll use the protocol spec file as our test file
    let input_path = Path::new("PROTOCOL_SPEC.md");
    let output_path = Path::new("received_file_async.md");
    
    // Open the input file
    let file = File::open(input_path).await?;
    let file_size = file.metadata().await?.len();
    let mut reader = BufReader::new(file);
    
    // Create output file
    let output_file = File::create(output_path).await?;
    let mut writer = BufWriter::new(output_file);
    
    println!("Transferring file: {} ({} bytes)", input_path.display(), file_size);
    
    // Create simulated network pipes
    // In a real application, these would be network streams
    let (mut client_write, mut server_read) = tokio::io::duplex(65536);
    
    // We'll use two tasks to simulate client and server
    let client_task = tokio::spawn(async move {
        // Create a stream sender with 16KB chunks
        let mut sender = client.stream_sender(&mut reader, Some(16384));
        
        // Stream data to the network
        let total_sent = sender.copy_to(&mut client_write).await?;
        println!("Client: Sent {} bytes", total_sent);
        
        // Close the connection when done
        let close_msg = client.close().await;
        client_write.write_all(&close_msg).await?;
        
        Ok::<_, pqc_protocol::error::Error>(total_sent)
    });
    
    let server_task = tokio::spawn(async move {
        // Create a stream receiver
        let mut receiver = server.stream_receiver(&mut writer, true);
        
        // Process all incoming data
        let total_received = receiver.process_reader(&mut server_read).await?;
        println!("Server: Received {} bytes", total_received);
        
        // Ensure all data is written
        writer.flush().await?;
        
        Ok::<_, pqc_protocol::error::Error>(total_received)
    });
    
    // Wait for both tasks to complete
    let (client_result, server_result) = tokio::join!(client_task, server_task);
    
    // Check results
    let total_sent = client_result??;
    let total_received = server_result??;
    
    println!("File transfer complete!");
    println!("Sent {} bytes total", total_sent);
    println!("Received {} bytes total", total_received);
    println!("Received file saved to: {}", output_path.display());
    
    Ok(())
}