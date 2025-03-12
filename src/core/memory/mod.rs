/*!
Memory management for the PQC protocol.

This module provides secure memory implementations for handling 
sensitive cryptographic material.
*/

// Secure memory implementation
pub mod secure_memory;

// Re-export the main components
pub use secure_memory::SecureMemory;