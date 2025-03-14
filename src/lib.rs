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

## Enhanced Security Features

This library includes enhanced security features to protect sensitive data:

- ZeroizeOnDrop ensures sensitive memory is wiped when no longer needed
- Heapless vectors avoid heap allocation risks with stack-based storage
- Protected memory using mprotect for read-only sensitive data
- Hardware security module integration for secure key storage when available
- Constant-time operations to prevent timing attacks
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

// Re-export enhanced security features for ease of use
pub use core::memory::{ZeroizeOnDrop, ProtectedMemory, SecureHeaplessVec, SecureVec32, SecureVec64};
pub use core::security::hardware_security::{HardwareSecurityManager, HardwareSecurityCapability};
pub use core::security::constant_time::{constant_time_eq, constant_time_select};

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