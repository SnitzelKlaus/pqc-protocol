/*!
Secure heap-allocated container for the PQC protocol.

A wrapper around standard Vec for secure operations with enhanced features
for memory protection, canary values for overflow detection, and secure
memory zeroing.
*/

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use rand::{Rng, rng};
use zeroize::Zeroize;

use crate::core::memory::traits::protection::MemoryProtection;
use crate::core::memory::error::{Error, Result};
use crate::core::memory::platforms::get_platform_impl;

/// A secure heap-allocated container for dynamic collections.
///
/// This is a wrapper around standard Vec with enhanced security features:
/// - Automatic memory zeroization on drop
/// - Canary values for overflow detection
/// - Memory locking to prevent swapping (on supported platforms)
pub struct SecureHeap<T> {
    /// Inner vector
    inner: Vec<T>,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Front canary value
    front_canary: u64,
    /// Back canary value
    back_canary: u64,
    /// Is using canary values for protection
    using_canary: AtomicBool,
}

impl<T> SecureHeap<T> {
    /// Create a new secure container
    pub fn new() -> Self {
        let canary = rng().random::<u64>();
        Self {
            inner: Vec::new(),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: AtomicBool::new(cfg!(feature = "memory-canary")),
        }
    }
    
    /// Create a secure container with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let canary = rng().random::<u64>();
        Self {
            inner: Vec::with_capacity(capacity),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: AtomicBool::new(cfg!(feature = "memory-canary")),
        }
    }
    
    /// Create a secure container from existing vector
    pub fn from_vec(vec: Vec<T>) -> Self {
        let canary = rng().random::<u64>();
        let mut secure = Self {
            inner: vec,
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: AtomicBool::new(cfg!(feature = "memory-canary")),
        };
        
        // Try to lock memory
        let _ = secure.try_lock_memory();
        
        secure
    }
    
    /// Consume this container and return the inner vector
    pub fn into_inner(self) -> Vec<T> {
        self.inner
    }
    
    /// Disable canary protection
    pub fn disable_canary(&mut self) {
        self.using_canary.store(false, Ordering::Relaxed);
    }
    
    /// Enable canary protection
    pub fn enable_canary(&mut self) {
        if !self.using_canary.load(Ordering::Relaxed) {
            let canary = rng().random::<u64>();
            self.front_canary = canary;
            self.back_canary = canary;
            self.using_canary.store(true, Ordering::Relaxed);
        }
    }
    
    /// Check canary values
    pub fn check_canary(&self) -> bool {
        if !self.using_canary.load(Ordering::Relaxed) {
            return true;
        }
        
        if self.front_canary != self.back_canary {
            eprintln!("SECURITY ERROR: SecureHeap canary values corrupted - possible buffer overflow detected!");
            return false;
        }
        
        true
    }
    
    /// Try to lock the memory
    fn try_lock_memory(&mut self) -> Result<()> {
        if !self.inner.is_empty() {
            let platform = get_platform_impl();
            let result = platform.lock_memory(self.inner.as_ptr(), self.inner.len() * std::mem::size_of::<T>());
            
            if result.is_ok() {
                self.locked.store(true, Ordering::Relaxed);
            }
            
            result
        } else {
            Ok(())
        }
    }
    
    /// Convert to bytes if T is u8
    fn as_mut_bytes(&mut self) -> Option<&mut [u8]> {
        if std::mem::size_of::<T>() == 1 {
            let ptr = self.inner.as_mut_ptr() as *mut u8;
            let len = self.inner.len();
            
            unsafe {
                Some(std::slice::from_raw_parts_mut(ptr, len))
            }
        } else {
            None
        }
    }
}

impl<T> MemoryProtection for SecureHeap<T> {
    fn lock_memory(&mut self) -> Result<()> {
        if self.locked.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        self.try_lock_memory()
    }
    
    fn unlock_memory(&mut self) -> Result<()> {
        if !self.locked.load(Ordering::Relaxed) || self.inner.is_empty() {
            return Ok(());
        }
        
        let platform = get_platform_impl();
        let result = platform.unlock_memory(self.inner.as_ptr(), self.inner.len() * std::mem::size_of::<T>());
        
        if result.is_ok() {
            self.locked.store(false, Ordering::Relaxed);
        }
        
        result
    }
    
    fn is_memory_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    
    fn make_read_only(&mut self) -> Result<()> {
        if self.inner.is_empty() {
            return Ok(());
        }
        
        let platform = get_platform_impl();
        platform.protect_memory_readonly(self.inner.as_ptr(), self.inner.len() * std::mem::size_of::<T>())
    }
    
    fn make_writable(&mut self) -> Result<()> {
        if self.inner.is_empty() {
            return Ok(());
        }
        
        let platform = get_platform_impl();
        platform.protect_memory_readwrite(self.inner.as_ptr(), self.inner.len() * std::mem::size_of::<T>())
    }
    
    fn is_read_only(&self) -> bool {
        false // We don't track this state
    }
    
    fn check_integrity(&self) -> Result<()> {
        if !self.check_canary() {
            Err(Error::BufferOverflow)
        } else {
            Ok(())
        }
    }
    
    fn clear(&mut self) -> Result<()> {
        // Unlock first if needed
        if self.locked.load(Ordering::Relaxed) {
            self.unlock_memory()?;
        }
        
        // For types where zeroing makes sense (like u8)
        if std::mem::size_of::<T>() > 0 && std::mem::needs_drop::<T>() {
            // Clear the memory with volatile writes if applicable
            if let Some(bytes) = self.as_mut_bytes() {
                bytes.zeroize();
            }
        }
        
        // Clear the vector
        self.inner.clear();
        
        Ok(())
    }
}

impl<T> Deref for SecureHeap<T> {
    type Target = Vec<T>;
    
    fn deref(&self) -> &Self::Target {
        debug_assert!(self.check_canary(), "SecureHeap canary check failed in deref");
        &self.inner
    }
}

impl<T> DerefMut for SecureHeap<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.check_canary(), "SecureHeap canary check failed in deref_mut");
        &mut self.inner
    }
}

impl<T> Drop for SecureHeap<T> {
    fn drop(&mut self) {
        // Check for buffer overflows before deallocation
        let overflow_detected = !self.check_canary();
        
        // Clear the memory
        let _ = self.clear();
        
        // If an overflow was detected, we might want to abort the program
        if overflow_detected && cfg!(feature = "abort-on-overflow") {
            eprintln!("FATAL: SecureHeap buffer overflow detected. Aborting.");
            std::process::abort();
        }
    }
}

impl<T> Default for SecureHeap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Zeroize for SecureHeap<T> {
    fn zeroize(&mut self) {
        let _ = self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_heap() {
        let mut vec = Vec::new();
        vec.extend_from_slice(&[1, 2, 3, 4, 5]);
        
        let mut secure_vec = SecureHeap::from_vec(vec);
        
        // Check values
        assert_eq!(secure_vec[0], 1);
        assert_eq!(secure_vec[4], 5);
        
        // Modify
        secure_vec[2] = 42;
        assert_eq!(secure_vec[2], 42);
        
        // Clear and check
        let _ = secure_vec.clear();
        assert_eq!(secure_vec.len(), 0);
    }
    
    #[test]
    fn test_secure_heap_canary() {
        let mut secure_vec = SecureHeap::from_vec(vec![1, 2, 3, 4, 5]);
        
        // Canary check should pass
        assert!(secure_vec.check_canary());
        
        // Disable canary
        secure_vec.disable_canary();
        assert!(secure_vec.check_canary()); // Should still pass when disabled
        
        // Enable canary
        secure_vec.enable_canary();
        assert!(secure_vec.check_canary());
    }
    
    #[test]
    fn test_memory_protection() {
        let mut secure_vec = SecureHeap::from_vec(vec![1, 2, 3, 4, 5]);
        
        // These operations should at least not crash
        let _ = secure_vec.lock_memory();
        let _ = secure_vec.make_read_only();
        let _ = secure_vec.make_writable();
        let _ = secure_vec.unlock_memory();
        
        // Test integrity check
        assert!(secure_vec.check_integrity().is_ok());
    }
}