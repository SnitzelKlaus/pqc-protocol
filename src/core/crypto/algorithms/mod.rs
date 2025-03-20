/*!
Implementations of cryptographic algorithms.

This module provides concrete implementations of the
cryptographic algorithm interfaces.
*/

// Key exchange algorithms
pub mod kex;

// Signature algorithms
pub mod signatures;

// Symmetric encryption algorithms
pub mod symmetric;

// Re-export factory functions
pub use kex::create_key_exchange;
pub use signatures::create_authenticator;
pub use symmetric::create_cipher;