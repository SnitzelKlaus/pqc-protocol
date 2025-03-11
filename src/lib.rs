/*!
# PQC Protocol

A streaming protocol using NIST's post-quantum cryptography algorithms
for secure communication across various platforms including C#, embedded systems,
and web browsers.

## Example

```rust
use pqc_protocol::{PqcSession, Result};

fn main() -> Result<()> {
    // Create client and server sessions
    let mut client_session = PqcSession::new()?;
    let mut server_session = PqcSession::new()?;
    
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
*/

// Re-export modules
pub mod error;
pub mod header;
pub mod session;
pub mod streaming;
pub mod types;

// Conditionally compile FFI module if the feature is enabled
#[cfg(feature = "ffi")]
pub mod ffi;

// Conditionally compile WASM module if the feature is enabled
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

// Re-export main types for convenience
pub use error::{Error, Result};
pub use header::MessageHeader;
pub use session::PqcSession;
pub use streaming::PqcStreamSender;
pub use types::MessageType;

/// The current version of the protocol
pub const VERSION: u8 = 1;