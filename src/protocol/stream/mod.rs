//! Streaming utilities for the PQC protocol.
//!
//! This module provides utilities for streaming data in chunks,
//! for both synchronous and asynchronous APIs.

// Common streaming functionality
pub mod common;

// Synchronous streaming implementation
pub mod sync_stream;

// Asynchronous streaming implementation (requires the "async" feature)
#[cfg(feature = "async")]
pub mod async_stream;