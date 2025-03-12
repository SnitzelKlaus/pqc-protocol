//! Foreign language bindings for the PQC protocol.
//!
//! This module provides interfaces to use the protocol from other languages,
//! including C/C++/C# via FFI and JavaScript/TypeScript via WebAssembly.

// Foreign Function Interface for C/C++/C#
#[cfg(feature = "ffi")]
pub mod ffi;

// WebAssembly bindings for browser
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;

// Re-export commonly used types for convenience
#[cfg(feature = "ffi")]
pub use ffi::c_api::*;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::bindings::*;