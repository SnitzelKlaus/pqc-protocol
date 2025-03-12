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
*/

// Core protocol components
pub mod core;

// Protocol implementation
pub mod protocol;

// Language bindings
pub mod bindings;

// Serialization support (optional)
#[cfg(feature = "serde-support")]
pub mod serde;

// Re-export commonly used types for convenience
pub use core::error::{Error, Result};
pub use core::message::{types::MessageType, format::MessageHeader};
pub use core::session::{state::SessionState, state::Role};
pub use core::constants::VERSION;

// Re-export synchronous API components for ease of use
pub mod sync {
    pub use crate::protocol::client::sync_client::PqcClient;
    pub use crate::protocol::server::sync_server::PqcServer;
    pub use crate::protocol::stream::sync_stream::{PqcSyncStreamSender, PqcSyncStreamReceiver, PqcReadExt, PqcWriteExt};
}

// Re-export asynchronous API components (enabled with the "async" feature)
#[cfg(feature = "async")]
pub mod r#async {
    pub use crate::protocol::client::async_client::AsyncPqcClient;
    pub use crate::protocol::server::async_server::AsyncPqcServer;
    pub use crate::protocol::stream::async_stream::{AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncPqcReadExt, AsyncPqcWriteExt};
}

// Internal shortcuts for protocol modules to access core components
pub(crate) mod abi {
    // Re-export crypto types for internal use
    pub use crate::core::crypto::{
        key_exchange::KyberPublicKey, 
        key_exchange::KyberSecretKey, 
        key_exchange::KyberCiphertext,
        auth::DilithiumPublicKey, 
        auth::DilithiumSecretKey, 
        auth::DilithiumSignature,
    };
    
    // Re-export session types for internal use
    pub use crate::core::session::{
        manager::SessionManager,
        state::{SessionState, Role, StateManager},
    };
    
    // Re-export commonly used error/message types for internal use
    pub use crate::core::message::{
        format::{MessageHeader, MessageBuilder, MessageParser},
        types::MessageType,
    };
}