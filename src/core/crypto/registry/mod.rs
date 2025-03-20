/*!
Registry for cryptographic algorithms.

This module provides a central registry for supported algorithms
to enable runtime selection and configuration.
*/

pub mod manager;

// Re-export registry manager functions
pub use manager::{
    get_registry, 
    register_key_exchange, 
    register_signature, 
    register_symmetric,
    get_key_exchange, 
    get_signature, 
    get_symmetric,
    list_key_exchange_algorithms, 
    list_signature_algorithms, 
    list_symmetric_algorithms
};