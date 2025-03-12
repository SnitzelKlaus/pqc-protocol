/*!
# PQC Protocol

A streaming protocol using NIST's post-quantum cryptography algorithms
for secure communication across various platforms including C#, embedded systems,
and web browsers.

## Overview

This library provides a post-quantum cryptography protocol implementation with:

- CRYSTALS-Kyber for key exchange
- CRYSTALS-Dilithium for digital signatures
- ChaCha20-Poly1305 for symmetric encryption
- Streaming support for large data transfers
- Cross-platform compatibility
- Both synchronous and asynchronous APIs

## Example (Synchronous API)

```rust
use pqc_protocol::sync::{PqcClient, PqcServer};
use pqc_protocol::error::Result;

fn main() -> Result<()> {
    // Create client and server sessions
    let mut client = PqcClient::new()?;
    let mut server = PqcServer::new()?;
    
    // Client initiates key exchange
    let client_public_key = client.connect()?;
    
    // Server accepts key exchange
    let (server_ct, server_vk) = server.accept(&client_public_key)?;
    
    // Client processes response to complete key exchange
    let client_vk = client.process_response(&server_ct)?;
    
    // Exchange verification keys and complete authentication
    server.authenticate(&client_vk)?;
    client.authenticate(&server_vk)?;
    
    // Now both sessions are fully established
    let message = b"Hello, post-quantum world!";
    let encrypted = client.send(message)?;
    let decrypted = server.receive(&encrypted)?;
    
    assert_eq!(message, &decrypted[..]);
    Ok(())
}
```

## Example (Asynchronous API)

```rust
use pqc_protocol::async::{AsyncPqcClient, AsyncPqcServer};
use pqc_protocol::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Create client and server sessions
    let client = AsyncPqcClient::new().await?;
    let server = AsyncPqcServer::new().await?;
    
    // Client initiates key exchange
    let client_pk = client.connect().await?;
    
    // Server accepts key exchange
    let (server_ct, server_vk) = server.accept(&client_pk).await?;
    
    // Client processes server response
    let client_vk = client.process_response(&server_ct).await?;
    
    // Authentication
    server.authenticate(&client_vk).await?;
    client.authenticate(&server_vk).await?;
    
    // Secure communication
    let message = b"Hello, async post-quantum world!";
    let encrypted = client.send(message).await?;
    let decrypted = server.receive(&encrypted).await?;
    
    assert_eq!(message, &decrypted[..]);
    Ok(())
}
```

## Streaming Example

```rust
use pqc_protocol::sync::{PqcClient, PqcServer};
use pqc_protocol::error::Result;

fn stream_large_data() -> Result<()> {
    // Set up secure connection (omitted for brevity)
    let mut client = PqcClient::new()?;
    let mut server = PqcServer::new()?;
    
    // ... establish connection ...
    
    // Stream large data
    let large_data = vec![0u8; 10 * 1024 * 1024]; // 10MB
    
    // Client streams data in chunks
    let sender = client.stream(large_data.as_slice(), Some(1024 * 1024));
    
    // Server receives and reassembles
    let mut receiver = server.create_receiver();
    
    for encrypted_chunk in sender {
        let encrypted = encrypted_chunk?;
        receiver.process_chunk(&encrypted)?;
    }
    
    // Get reassembled data
    let received_data = receiver.take_reassembled_data().unwrap();
    assert_eq!(received_data.len(), large_data.len());
    
    Ok(())
}
```

## Features

- `std` (default): Standard library support
- `async`: Async support with Tokio
- `serde-support`: Serialization support with serde
- `ffi`: Foreign Function Interface for C/C++/C#
- `wasm`: WebAssembly support
*/

// Public modules
pub mod constants;
pub mod error;
pub mod message;
pub mod crypto;
pub mod session;
pub mod streaming;
pub mod memory;
pub mod security;

pub mod client;
pub mod server;
pub mod stream;

// Optional modules 
#[cfg(feature = "serde-support")] 
pub mod serde; 

#[cfg(feature = "ffi")] 
pub mod ffi; 

#[cfg(all(feature = "wasm", target_arch = "wasm32"))] 
pub mod wasm;

// Re-export synchronous API components for ease of use 
pub mod sync { 
    pub use crate::client::sync_client::PqcClient; 
    pub use crate::server::sync_server::PqcServer; 
    pub use crate::stream::sync_stream::{PqcSyncStreamSender, PqcSyncStreamReceiver, PqcReadExt, PqcWriteExt}; 
}

// Re-export asynchronous API components (enabled with the "async" feature) 
#[cfg(feature = "async")] 
pub mod r#async { 
    pub use crate::client::async_client::AsyncPqcClient; 
    pub use crate::server::async_server::AsyncPqcServer; 
    pub use crate::stream::async_stream::{AsyncPqcSendStream, AsyncPqcReceiveStream, AsyncPqcReadExt, AsyncPqcWriteExt}; 
}

// Re-export commonly used types for convenience 
pub use error::{Error, Result}; 
pub use message::{MessageType, MessageHeader}; 
pub use session::{PqcSession, SessionState, Role}; 
pub use streaming::{PqcStreamSender, PqcStreamReceiver};

// Export protocol version
/// The current version of the protocol
pub use constants::VERSION;