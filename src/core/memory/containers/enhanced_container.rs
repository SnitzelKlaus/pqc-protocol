/*!
Enhanced secure memory implementation for the PQC protocol.

This module provides advanced secure memory implementations with
additional protections like read-only memory when not in use.
*/

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::memory::containers::base_container::SecureContainer;
use crate::core::memory::traits::zeroize::Zeroize;
use crate::core::memory::traits::protection::MemoryProtection;
use crate::core::memory::error::{Error, Result};

/// Advanced secure memory container with additional protection mechanisms.
/// This version uses platform-specific mechanisms to create read-only pages when not in use.
/// Available with the "memory-enhanced" feature
pub struct EnhancedContainer<T: Sized> {
    /// The secure memory container
    memory: SecureContainer<T>,
    /// Whether the memory is currently read-only
    read_only: AtomicBool,
}

impl<T: Sized> EnhancedContainer<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        Self {
            memory: SecureContainer::new(value),
            read_only: AtomicBool::new(false),
        }
    }
    
    /// Make the memory read-only
    pub fn make_read_only(&self) -> bool {
        if self.is_read_only() {
            return true;
        }
        
        let result = self.memory.make_read_only();
        
        if result.is_ok() {
            self.read_only.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    
    /// Make the memory writable
    pub fn make_writable(&self) -> bool {
        if !self.is_read_only() {
            return true;
        }
        
        let result = self.memory.make_writable();
        
        if result.is_ok() {
            self.read_only.store(false, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureContainer<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably (automatically makes it writable first)
    pub fn inner_mut(&mut self) -> &mut SecureContainer<T> {
        // Ensure memory is writable
        self.make_writable();
        &mut self.memory
    }
}

impl<T: Sized> MemoryProtection for EnhancedContainer<T> {
    fn lock_memory(&mut self) -> Result<()> {
        self.memory.lock_memory()
    }
    
    fn unlock_memory(&mut self) -> Result<()> {
        self.memory.unlock_memory()
    }
    
    fn is_memory_locked(&self) -> bool {
        self.memory.is_memory_locked()
    }
    
    fn make_read_only(&mut self) -> Result<()> {
        if self.read_only.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        let result = self.memory.make_read_only();
        
        if result.is_ok() {
            self.read_only.store(true, Ordering::Relaxed);
        }
        
        result
    }
    
    fn make_writable(&mut self) -> Result<()> {
        if !self.read_only.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        let result = self.memory.make_writable();
        
        if result.is_ok() {
            self.read_only.store(false, Ordering::Relaxed);
        }
        
        result
    }
    
    fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
    
    fn check_integrity(&self) -> Result<()> {
        self.memory.check_integrity()
    }
    
    fn clear(&mut self) -> Result<()> {
        // Make writable before clearing
        if self.is_read_only() {
            self.make_writable()?;
        }
        
        self.memory.clear()
    }
}

impl<T: Sized> Deref for EnhancedContainer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &*self.memory
    }
}

impl<T: Sized> DerefMut for EnhancedContainer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Make writable before allowing mutation
        if self.is_read_only() {
            let _ = self.make_writable();
        }
        
        &mut *self.memory
    }
}

impl<T: Sized + Default> Default for EnhancedContainer<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Sized + Clone> Clone for EnhancedContainer<T> {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory.clone(),
            read_only: AtomicBool::new(self.is_read_only()),
        }
    }
}

impl<T: Sized> Zeroize for EnhancedContainer<T> {
    fn zeroize(&mut self) {
        // Make writable before zeroizing
        if self.is_read_only() {
            let _ = self.make_writable();
        }
        
        self.memory.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_container() {
        let mut enhanced = EnhancedContainer::new([0u8; 32]);
        
        // Should start as writable
        assert!(!enhanced.is_read_only());
        
        // Set some values
        enhanced[0] = 42;
        enhanced[1] = 43;
        
        // Make read-only
        let result = enhanced.make_read_only();
        println!("Make read-only result: {}", result);
        
        if result {
            assert!(enhanced.is_read_only());
            
            // We can still read
            assert_eq!(enhanced[0], 42);
            
            // Access via deref_mut should make writable again
            enhanced[2] = 44;
            assert!(!enhanced.is_read_only());
            
            // Check values
            assert_eq!(enhanced[0], 42);
            assert_eq!(enhanced[1], 43);
            assert_eq!(enhanced[2], 44);
        }
        
        // Make writable again explicitly
        enhanced.make_writable();
        assert!(!enhanced.is_read_only());
        
        // Test MemoryProtection trait methods
        let _ = enhanced.make_read_only();
        if enhanced.is_read_only() {
            let _ = enhanced.make_writable();
            assert!(!enhanced.is_read_only());
        }
        
        // Test clear
        let _ = enhanced.clear();
        assert_eq!(enhanced[0], 0);
    }
}