//! Protocol implementation for PQC.
//!
//! This module contains the concrete implementation of the protocol,
//! including client and server components as well as streaming functionality.

// Client implementation
pub mod client;

// Server implementation
pub mod server;

// Streaming utilities
pub mod stream;

// Shared implementation
pub mod shared;

// Builder
pub mod builder;

// Re-export for convenience
pub use client::sync_client::PqcClient;
pub use server::sync_server::PqcServer;
pub use stream::sync_stream::{PqcSyncStreamSender, PqcSyncStreamReceiver, PqcReadExt, PqcWriteExt};

// Re-export async components when the "async" feature is enabled
#[cfg(feature = "async")]
pub use client::async_client::AsyncPqcClient;
#[cfg(feature = "async")]
pub use server::async_server::AsyncPqcServer;
#[cfg(feature = "async")]
pub use stream::async_stream::{AsyncPqcStreamSender, AsyncPqcStreamReceiver, AsyncPqcReadExt, AsyncPqcWriteExt};