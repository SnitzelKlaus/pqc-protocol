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

## Example

```rust
use pqc_protocol::{PqcSession, Result};

fn main() -> Result<()> {
    // Create client and server sessions
    let mut client_session = PqcSession::new()?;
    let mut server_session = PqcSession::new()?;
    server_session.set_role(pqc_protocol::session::Role::Server);
    
    // Client initiates key exchange
    let client_public_key = client_session.init_key_exchange()?;
    
    // Server accepts key exchange
    let ciphertext = server_session.accept_key_exchange(&client_public_key)?;
    
    // Client processes response to complete key exchange
    client_session.process_key_exchange(&ciphertext)?;
    
    // Exchange verification keys and complete authentication.
    client_session.set_remote_verification_key(server_session.local_verification_key().clone())?;
    server_session.set_remote_verification_key(client_session.local_verification_key().clone())?;
    client_session.complete_authentication()?;
    server_session.complete_authentication()?;
    
    // Now both sessions are fully established.
    let message = b"Hello, post-quantum world!";
    let encrypted = client_session.encrypt_and_sign(message)?;
    let decrypted = server_session.verify_and_decrypt(&encrypted)?;
    
    assert_eq!(message, &decrypted[..]);
    Ok(())
}
```

## High-Level API Example

```rust
use pqc_protocol::api::{PqcClient, PqcServer};

// Client side
let mut client = PqcClient::new()?;
let client_pk = client.connect()?;

// Server side
let mut server = PqcServer::new()?;
let (server_ct, server_vk) = server.accept(&client_pk)?;

// Client continues
let client_vk = client.process_response(&server_ct)?;
client.authenticate(&server_vk)?;

// Server continues
server.authenticate(&client_vk)?;

// Secure communication
let encrypted = client.send(b"Hello!")?;
let decrypted = server.receive(&encrypted)?;
```
*/

// Public modules
pub mod constants;
pub mod error;
pub mod message;
pub mod crypto;
pub mod session;
pub mod streaming;
pub mod api;

// Optional serde support
#[cfg(feature = "serde-support")]
pub mod serde;

// Conditionally compile FFI module if the feature is enabled
#[cfg(feature = "ffi")]
pub mod ffi;

// Conditionally compile WASM module if the feature is enabled
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

// Re-export commonly used types for convenience
pub use error::{Error, Result};
pub use message::{MessageType, MessageHeader};
pub use session::{PqcSession, SessionState, Role};
pub use streaming::{PqcStreamSender, PqcStreamReceiver};

// Export protocol version
/// The current version of the protocol
pub use constants::VERSION;