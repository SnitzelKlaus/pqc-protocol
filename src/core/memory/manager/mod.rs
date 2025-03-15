/*!
Memory management for secure memory operations.

This module provides the memory manager and configuration
for secure memory operations.
*/

pub mod config;
pub mod memory_manager;

// Re-export manager components
pub use config::{Platform, MemoryConfig, for_current_platform};
pub use memory_manager::SecureMemoryManager;