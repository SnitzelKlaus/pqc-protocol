//! Server implementations for the PQC protocol.
//!
//! This module provides server-side implementations for both
//! synchronous and asynchronous APIs.

// Common server functionality
pub mod common;

// Synchronous server implementation
pub mod sync_server;

// Asynchronous server implementation (requires the "async" feature)
#[cfg(feature = "async")]
pub mod async_server;