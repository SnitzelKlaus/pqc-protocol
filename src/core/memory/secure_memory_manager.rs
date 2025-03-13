/*!
Secure memory manager for the PQC protocol.

This module provides a central manager for secure memory operations,
including creation, management, and security settings for sensitive data.
*/

use std::sync::atomic::{AtomicBool, Ordering};

use super::memory_security::MemorySecurity;
use super::secure_memory::SecureMemory;
use super::secure_vec::SecureVec;
use super::zeroize::{Zeroize, secure_zero_memory};

/// Manages secure memory for a session
pub struct SecureMemoryManager {
    /// Current memory security level
    level: MemorySecurity,
    
    /// Whether automatic key erasure is enabled
    auto_erase: bool,
    
    /// Whether memory locking is enabled
    memory_locking: AtomicBool,
    
    /// Whether canary values are used for buffer overflow detection
    canary_protection: AtomicBool,
    
    /// Whether sensitive memory is zeroed when freed
    zero_on_free: AtomicBool,
}

impl SecureMemoryManager {
    /// Create a new secure memory manager with the specified security level
    pub fn new(level: MemorySecurity) -> Self {
        let manager = Self {
            level,
            auto_erase: true,
            #[cfg(feature = "memory-lock")]
            memory_locking: AtomicBool::new(true),
            #[cfg(not(feature = "memory-lock"))]
            memory_locking: AtomicBool::new(false),
            
            #[cfg(feature = "memory-canary")]
            canary_protection: AtomicBool::new(true),
            #[cfg(not(feature = "memory-canary"))]
            canary_protection: AtomicBool::new(false),
            
            #[cfg(feature = "memory-zero")]
            zero_on_free: AtomicBool::new(true),
            #[cfg(not(feature = "memory-zero"))]
            zero_on_free: AtomicBool::new(false),
        };
        
        manager
    }
    
    /// Create a new secure memory manager with default security level
    pub fn default() -> Self {
        Self::new(MemorySecurity::Standard)
    }
    
    /// Create a new secure memory manager with enhanced security
    pub fn enhanced() -> Self {
        Self::new(MemorySecurity::Enhanced)
    }
    
    /// Create a new secure memory manager with maximum security
    pub fn maximum() -> Self {
        Self::new(MemorySecurity::Maximum)
    }
    
    /// Get the current security level
    pub fn security_level(&self) -> MemorySecurity {
        self.level
    }
    
    /// Set the security level
    pub fn set_security_level(&mut self, level: MemorySecurity) {
        self.level = level;
    }
    
    /// Check if memory locking is enabled
    pub fn is_memory_locking_enabled(&self) -> bool {
        self.memory_locking.load(Ordering::Relaxed)
    }
    
    /// Enable memory locking
    pub fn enable_memory_locking(&self) {
        self.memory_locking.store(true, Ordering::Relaxed);
    }
    
    /// Disable memory locking
    pub fn disable_memory_locking(&self) {
        self.memory_locking.store(false, Ordering::Relaxed);
    }
    
    /// Check if canary protection is enabled
    pub fn is_canary_protection_enabled(&self) -> bool {
        self.canary_protection.load(Ordering::Relaxed)
    }
    
    /// Enable canary protection
    pub fn enable_canary_protection(&self) {
        self.canary_protection.store(true, Ordering::Relaxed);
    }
    
    /// Disable canary protection
    pub fn disable_canary_protection(&self) {
        self.canary_protection.store(false, Ordering::Relaxed);
    }
    
    /// Check if zero-on-free is enabled
    pub fn is_zero_on_free_enabled(&self) -> bool {
        self.zero_on_free.load(Ordering::Relaxed)
    }
    
    /// Enable zero-on-free
    pub fn enable_zero_on_free(&self) {
        self.zero_on_free.store(true, Ordering::Relaxed);
    }
    
    /// Disable zero-on-free
    pub fn disable_zero_on_free(&self) {
        self.zero_on_free.store(false, Ordering::Relaxed);
    }
    
    /// Check if auto-erase is enabled
    pub fn is_auto_erase_enabled(&self) -> bool {
        self.auto_erase
    }
    
    /// Enable auto-erase
    pub fn enable_auto_erase(&mut self) {
        self.auto_erase = true;
    }
    
    /// Disable auto-erase
    pub fn disable_auto_erase(&mut self) {
        self.auto_erase = false;
    }
    
    /// Create a secure memory container for sensitive data
    pub fn secure_memory<T>(&self, value: T) -> SecureMemory<T> {
        SecureMemory::new(value)
    }
    
    /// Create a secure vector container
    pub fn secure_vec<T>(&self) -> SecureVec<T> {
        SecureVec::new()
    }
    
    /// Create a secure vector with capacity
    pub fn secure_vec_with_capacity<T>(&self, capacity: usize) -> SecureVec<T> {
        SecureVec::with_capacity(capacity)
    }
    
    /// Create a secure vector from an existing vector
    pub fn secure_vec_from_vec<T>(&self, vec: Vec<T>) -> SecureVec<T> {
        SecureVec::from_vec(vec)
    }
    
    /// Securely wipe a key from memory
    pub fn wipe_key<T: Zeroize>(&self, key: &mut T) {
        key.zeroize();
    }
    
    /// Apply current security settings to an existing SecureMemory container
    pub fn apply_settings_to_memory<T>(&self, _memory: &mut SecureMemory<T>) {
        // This is a placeholder - in a real implementation, we would
        // modify the security settings of the memory container
    }
    
    /// Apply current security settings to an existing SecureVec container
    pub fn apply_settings_to_vec<T>(&self, vec: &mut SecureVec<T>) {
        if self.is_canary_protection_enabled() {
            vec.enable_canary();
        } else {
            vec.disable_canary();
        }
    }
    
    /// Zero out sensitive memory regions
    pub fn zeroize_region(&self, region: &mut [u8]) {
        secure_zero_memory(region);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_manager() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Test creating secure memory through the manager
        let secure_mem = memory_manager.secure_memory([0u8; 32]);
        
        #[cfg(feature = "memory-lock")]
        assert!(secure_mem.is_locked());
        
        // Test creating secure vector through the manager
        let secure_vec = memory_manager.secure_vec_from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(secure_vec[0], 1);
        
        // Test security settings
        #[cfg(feature = "memory-lock")]
        assert!(memory_manager.is_memory_locking_enabled());
        
        #[cfg(feature = "memory-canary")]
        assert!(memory_manager.is_canary_protection_enabled());
        
        #[cfg(feature = "memory-zero")]
        assert!(memory_manager.is_zero_on_free_enabled());
        
        // Test security level
        assert_eq!(memory_manager.security_level(), MemorySecurity::Enhanced);
    }
    
    #[test]
    fn test_security_settings() {
        let mut manager = SecureMemoryManager::default();
        
        // Test default settings
        assert_eq!(manager.security_level(), MemorySecurity::Standard);
        
        #[cfg(feature = "memory-lock")]
        {
            assert!(manager.is_memory_locking_enabled());
            manager.disable_memory_locking();
            assert!(!manager.is_memory_locking_enabled());
            manager.enable_memory_locking();
            assert!(manager.is_memory_locking_enabled());
        }
        
        #[cfg(feature = "memory-canary")]
        {
            assert!(manager.is_canary_protection_enabled());
            manager.disable_canary_protection();
            assert!(!manager.is_canary_protection_enabled());
            manager.enable_canary_protection();
            assert!(manager.is_canary_protection_enabled());
        }
        
        assert!(manager.is_auto_erase_enabled());
        manager.disable_auto_erase();
        assert!(!manager.is_auto_erase_enabled());
        manager.enable_auto_erase();
        assert!(manager.is_auto_erase_enabled());
    }
    
    #[test]
    fn test_wipe_key() {
        let manager = SecureMemoryManager::default();
        let mut key = vec![42u8; 32];
        
        // All bytes should be 42
        for byte in &key {
            assert_eq!(*byte, 42);
        }
        
        // Wipe the key
        manager.wipe_key(&mut key);
        
        // All bytes should be zeroed
        for byte in &key {
            assert_eq!(*byte, 0);
        }
    }
}