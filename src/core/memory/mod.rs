/*!
Memory management for the PQC protocol.

This module provides secure memory implementations for handling 
sensitive cryptographic material and platform-specific memory configurations.
*/

// Secure memory implementation
pub mod secure_memory;
pub mod secure_vec;
pub mod zeroize;

// Memory security levels and traits
pub mod memory_security;

// Memory management
pub mod secure_memory_manager;

// Enhanced memory protection (feature-gated)
#[cfg(feature = "memory-enhanced")]
pub mod enhanced_memory;

// WebAssembly specific memory manager
#[cfg(all(target_arch = "wasm32", feature = "wasm-compat"))]
pub mod wasm_memory;

// Platform-specific memory configuration
pub mod config;

// Re-export the main components
pub use secure_memory::SecureMemory;
pub use secure_vec::SecureVec;
pub use zeroize::{Zeroize, secure_zero_memory};

// Re-export memory manager components
pub use secure_memory_manager::SecureMemoryManager;
pub use memory_security::MemorySecurity;
pub use memory_security::SecureSession;

// Re-export enhanced memory components if feature is enabled
#[cfg(feature = "memory-enhanced")]
pub use enhanced_memory::EnhancedSecureMemory;

// Re-export WASM memory components for WebAssembly targets
#[cfg(all(target_arch = "wasm32", feature = "wasm-compat"))]
pub use wasm_memory::WasmMemoryManager;

// Re-export memory configuration components
pub use config::{
    Platform,
    MemoryConfig,
    auto_detect_platform,
    for_current_platform,
};