/*!
Memory management for the PQC protocol.

This module provides secure memory implementations for handling 
sensitive cryptographic material and platform-specific memory configurations.
*/

// Re-export main modules
pub mod api;
pub mod error;

// Core traits
pub mod traits;

// Container implementations
pub mod containers;

// Utility functions
pub mod utils;

// Memory manager
pub mod manager;

// Hardware security (feature-gated)
#[cfg(feature = "hardware-security")]
pub mod hardware;

// Re-export the main components for easy access
pub use error::{Error, Result};
pub use traits::zeroize::{Zeroize, secure_zero_memory};
pub use traits::protection::MemoryProtection;
pub use traits::security::{MemorySecurity, SecureSession, SecureMemoryFactory};

pub use containers::base_container::SecureContainer;
pub use containers::readonly_container::ReadOnlyContainer;
pub use containers::heap_container::SecureHeap;
pub use containers::stack_container::{SecureStack, SecureStack32, SecureStack64};

pub use utils::zeroize_on_drop::ZeroizeOnDrop;

pub use manager::memory_manager::SecureMemoryManager;
pub use manager::config::{Platform, MemoryConfig, for_current_platform};

// Optional re-exports based on features
#[cfg(feature = "memory-enhanced")]
pub use containers::enhanced_container::EnhancedContainer;

#[cfg(target_arch = "wasm32")]
pub use platform::wasm::WasmMemoryManager;

/// Type aliases for backward compatibility
pub type SecureMemory<T> = SecureContainer<T>;
pub type SecureVec<T> = SecureHeap<T>;
pub type SecureHeaplessVec<T, const N: usize> = SecureStack<T, N>;
pub type ProtectedMemory<T> = ReadOnlyContainer<T>;
pub type ProtectedKey32 = ReadOnlyContainer<[u8; 32]>;