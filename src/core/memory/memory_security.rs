/*!
Memory security levels and management for the PQC protocol.

This module defines different security levels for memory protection
and the secure session trait.
*/

use super::secure_memory_manager::SecureMemoryManager;

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
        self.memory_manager().enable_memory_locking();
    }
    
    /// Disable memory locking
    fn disable_memory_locking(&mut self) {
        self.memory_manager().disable_memory_locking();
    }
    
    /// Enable canary protection
    fn enable_canary_protection(&mut self) {
        self.memory_manager().enable_canary_protection();
    }
    
    /// Disable canary protection
    fn disable_canary_protection(&mut self) {
        self.memory_manager().disable_canary_protection();
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

#[cfg(test)]
mod tests {
    use super::*;
    
    // Test struct implementing SecureSession
    struct TestSession {
        manager: SecureMemoryManager,
    }
    
    impl SecureSession for TestSession {
        fn memory_manager(&self) -> &SecureMemoryManager {
            &self.manager
        }
        
        fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager {
            &mut self.manager
        }
        
        fn erase_sensitive_memory(&mut self) {
            // Just a test implementation
        }
    }
    
    #[test]
    fn test_security_levels() {
        let mut session = TestSession {
            manager: SecureMemoryManager::default(),
        };
        
        // Test default level
        assert_eq!(session.memory_security_level(), MemorySecurity::Standard);
        
        // Change level
        session.set_memory_security_level(MemorySecurity::Enhanced);
        assert_eq!(session.memory_security_level(), MemorySecurity::Enhanced);
        
        // Test secure status
        assert!(session.is_memory_secure());
        
        // Disable features and check again
        session.disable_memory_locking();
        assert!(!session.is_memory_secure());
    }
}