/*!
Memory management for the PQC protocol.

This module provides secure memory implementations for handling 
sensitive cryptographic material and platform-specific memory configurations.
*/

// Secure memory implementation
pub mod secure_memory;
pub mod secure_memory_manager;

// Platform-specific memory configuration
pub mod config;

// Re-export the main components
pub use secure_memory::{
    SecureMemory,
    SecureVec,
    Zeroize,
    secure_zero_memory,
};

// Re-export memory manager components
pub use secure_memory_manager::SecureMemoryManager;
pub use secure_memory_manager::MemorySecurity;
pub use secure_memory_manager::SecureSession;

// Re-export memory configuration components
pub use config::{
    Platform,
    MemoryConfig,
    auto_detect_platform,
    for_current_platform,
};