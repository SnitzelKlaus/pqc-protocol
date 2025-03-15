/*!
Memory security levels and management traits.

This module defines different security levels for memory protection
and the secure session trait.
*/

use crate::core::memory::manager::memory_manager::SecureMemoryManager;
use crate::core::memory::containers::{
    base_container::SecureContainer,
    readonly_container::ReadOnlyContainer,
    heap_container::SecureHeap,
    stack_container::SecureStack
};

/// Memory security level options for session data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySecurity {
    /// Standard security: basic protections
    Standard,
    /// Enhanced security: additional protections and canary values
    Enhanced,
    /// Maximum security: all protections enabled, read-only when not in use
    Maximum,
}

impl Default for MemorySecurity {
    fn default() -> Self {
        MemorySecurity::Standard
    }
}

/// Trait for session objects that use secure memory
pub trait SecureSession {
    /// Get memory security manager
    fn memory_manager(&self) -> &SecureMemoryManager;
    
    /// Get mutable reference to memory security manager
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager;
    
    /// Set memory security level
    fn set_memory_security_level(&mut self, level: MemorySecurity) {
        self.memory_manager_mut().set_security_level(level);
    }
    
    /// Get current memory security level
    fn memory_security_level(&self) -> MemorySecurity {
        self.memory_manager().security_level()
    }
    
    /// Enable memory locking
    fn enable_memory_locking(&mut self) {
        self.memory_manager_mut().enable_memory_locking();
    }
    
    /// Disable memory locking
    fn disable_memory_locking(&mut self) {
        self.memory_manager_mut().disable_memory_locking();
    }
    
    /// Enable canary protection
    fn enable_canary_protection(&mut self) {
        self.memory_manager_mut().enable_canary_protection();
    }
    
    /// Disable canary protection
    fn disable_canary_protection(&mut self) {
        self.memory_manager_mut().disable_canary_protection();
    }
    
    /// Check if memory is secure
    fn is_memory_secure(&self) -> bool {
        let manager = self.memory_manager();
        manager.is_memory_locking_enabled() &&
        manager.is_canary_protection_enabled() &&
        manager.is_zero_on_free_enabled()
    }
    
    /// Erase sensitive memory
    fn erase_sensitive_memory(&mut self);
}

/// Factory trait for creating secure memory containers
pub trait SecureMemoryFactory {
    /// Create a new secure memory container for a value
    fn create_secure_container<T>(&self, value: T) -> SecureContainer<T>;
    
    /// Create a secure heap-based container
    fn create_secure_heap<T>(&self) -> SecureHeap<T>;
    
    /// Create a secure stack-based container
    fn create_secure_stack<T, const N: usize>(&self) -> SecureStack<T, N>;
    
    /// Create a protected memory container that can be made read-only
    fn create_readonly_container<T: Sized>(&self, value: T) -> ReadOnlyContainer<T>;
}