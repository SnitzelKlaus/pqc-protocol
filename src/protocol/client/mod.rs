//! Client implementations for the PQC protocol.
//!
//! This module provides client-side implementations for both
//! synchronous and asynchronous APIs.

// Common client functionality
pub mod common;

// Synchronous client implementation
pub mod sync_client;

// Asynchronous client implementation (requires the "async" feature)
#[cfg(feature = "async")]
pub mod async_client;