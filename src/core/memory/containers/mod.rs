/*!
Secure memory container implementations.

This module provides various secure memory containers for different use cases:
- Base containers for general secure memory
- Read-only containers that can be protected from modification
- Heap-based containers for dynamic allocation
- Stack-based containers for fixed-size allocation
*/

pub mod base_container;
pub mod readonly_container;
pub mod heap_container;
pub mod stack_container;

// Optional enhanced containers
#[cfg(feature = "memory-enhanced")]
pub mod enhanced_container;

// Re-export container types with clearer names
pub use base_container::SecureContainer;
pub use readonly_container::ReadOnlyContainer;
pub use heap_container::SecureHeap;
pub use stack_container::{SecureStack, SecureStack32, SecureStack64};

#[cfg(feature = "memory-enhanced")]
pub use enhanced_container::EnhancedContainer;