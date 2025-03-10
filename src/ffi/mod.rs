/*!
Foreign Function Interface (FFI) module for the PQC protocol.

This module provides C-compatible bindings to the PQC protocol,
allowing it to be used from C, C++, C#, and other languages
that support C FFI.
*/

mod c_api;

pub use c_api::*;