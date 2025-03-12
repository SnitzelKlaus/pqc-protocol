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
- Configurable cryptographic algorithms
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
pub use core::error::{Error, Result, AuthError, CryptoError, KeyExchangeError};
pub use core::message::{MessageType, MessageHeader, MessageBuilder, MessageParser};
pub use core::session::{SessionState, Role, PqcSession};
pub use core::constants::{VERSION, MAX_CHUNK_SIZE, sizes};
pub use core::crypto::{KyberPublicKey, KyberSecretKey, KyberCiphertext, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature};
pub use core::security::rotation::PqcSessionKeyRotation;

// Re-export crypto configuration and registry
pub use core::crypto::config::{CryptoConfig, KeyExchangeAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};
pub use core::crypto::registry::{
    register_key_exchange, register_signature, register_symmetric,
    list_key_exchange_algorithms, list_signature_algorithms, list_symmetric_algorithms
};

// Re-export protocol builder
pub use protocol::builder::{PqcProtocolBuilder, client, server};
#[cfg(feature = "async")]
pub use protocol::builder::{async_client, async_server};

// Re-export shared traits
pub use protocol::shared::traits::{
    PqcEndpoint, PqcClientEndpoint, PqcServerEndpoint, PqcKeyRotation,
    PqcStreamSender, PqcStreamReceiver, PqcConfigurable, PqcMemoryControl,
    UnifiedPqcClient, UnifiedPqcServer
};

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