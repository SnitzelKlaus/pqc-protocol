/*!
Secure vector implementation for the PQC protocol.

A wrapper around standard Vec for secure operations with enhanced features
for memory protection, canary values for overflow detection, and secure
memory zeroing.
*/

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use super::zeroize::{Zeroize, secure_zero_memory};
use rand::{Rng, thread_rng};

/// A wrapper around standard Vec for secure operations with enhanced features
pub struct SecureVec<T> {
    /// Inner vector
    inner: Vec<T>,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Front canary value
    front_canary: u64,
    /// Back canary value
    back_canary: u64,
    /// Is using canary values for protection
    using_canary: bool,
}

impl<T> SecureVec<T> {
    /// Create a new secure vector
    pub fn new() -> Self {
        let canary = thread_rng().gen::<u64>();
        Self {
            inner: Vec::new(),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        }
    }
    
    /// Create a secure vector with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let canary = thread_rng().gen::<u64>();
        Self {
            inner: Vec::with_capacity(capacity),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        }
    }
    
    /// Create a secure vector from existing vector
    pub fn from_vec(vec: Vec<T>) -> Self {
        let canary = thread_rng().gen::<u64>();
        let mut secure = Self {
            inner: vec,
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        };
        
        // Try to lock memory
        secure.try_lock_memory();
        
        secure
    }
    
    /// Disable canary protection
    pub fn disable_canary(&mut self) {
        self.using_canary = false;
    }
    
    /// Enable canary protection
    pub fn enable_canary(&mut self) {
        if !self.using_canary {
            let canary = thread_rng().gen::<u64>();
            self.front_canary = canary;
            self.back_canary = canary;
            self.using_canary = true;
        }
    }
    
    /// Check canary values
    pub fn check_canary(&self) -> bool {
        if !self.using_canary {
            return true;
        }
        
        if self.front_canary != self.back_canary {
            eprintln!("SECURITY ERROR: SecureVec canary values corrupted - possible buffer overflow detected!");
            return false;
        }
        
        true
    }
    
    /// Try to lock the memory
    fn try_lock_memory(&mut self) {
        if !self.inner.is_empty() {
            #[cfg(unix)]
            unsafe {
                use libc::mlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                if mlock(ptr as *const _, size) == 0 {
                    self.locked.store(true, Ordering::Relaxed);
                }
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            unsafe {
                use winapi::um::memoryapi::VirtualLock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                if VirtualLock(ptr as *mut _, size) != 0 {
                    self.locked.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    
    /// Check if memory is locked
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    
    /// Clear the memory with secure zeroization
    pub fn clear(&mut self) {
        // Unlock first if needed
        if self.locked.load(Ordering::Relaxed) {
            #[cfg(unix)]
            unsafe {
                use libc::munlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                munlock(ptr as *const _, size);
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            unsafe {
                use winapi::um::memoryapi::VirtualUnlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                VirtualUnlock(ptr as *mut _, size);
            }
            
            self.locked.store(false, Ordering::Relaxed);
        }
        
        // For types where zeroing makes sense (like u8)
        if std::mem::size_of::<T>() > 0 && std::mem::needs_drop::<T>() {
            // Clear the memory with volatile writes if applicable
            if let Some(bytes) = self.as_mut_bytes() {
                secure_zero_memory(bytes);
            }
        }
        
        // Clear the vector
        self.inner.clear();
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

impl<T> Deref for SecureVec<T> {
    type Target = Vec<T>;
    
    fn deref(&self) -> &Self::Target {
        debug_assert!(self.check_canary(), "SecureVec canary check failed in deref");
        &self.inner
    }
}

impl<T> DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.check_canary(), "SecureVec canary check failed in deref_mut");
        &mut self.inner
    }
}

impl<T> Drop for SecureVec<T> {
    fn drop(&mut self) {
        // Check for buffer overflows before deallocation
        let overflow_detected = !self.check_canary();
        
        // Clear the memory
        self.clear();
        
        // If an overflow was detected, we might want to abort the program
        if overflow_detected && cfg!(feature = "abort-on-overflow") {
            eprintln!("FATAL: SecureVec buffer overflow detected. Aborting.");
            std::process::abort();
        }
    }
}

impl<T> Default for SecureVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Zeroize for SecureVec<T> {
    fn zeroize(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_vec() {
        let mut vec = Vec::new();
        vec.extend_from_slice(&[1, 2, 3, 4, 5]);
        
        let mut secure_vec = SecureVec::from_vec(vec);
        
        // Check values
        assert_eq!(secure_vec[0], 1);
        assert_eq!(secure_vec[4], 5);
        
        // Modify
        secure_vec[2] = 42;
        assert_eq!(secure_vec[2], 42);
        
        // Clear and check
        secure_vec.clear();
        assert_eq!(secure_vec.len(), 0);
    }
    
    #[test]
    fn test_secure_vec_canary() {
        let mut secure_vec = SecureVec::from_vec(vec![1, 2, 3, 4, 5]);
        
        // Canary check should pass
        assert!(secure_vec.check_canary());
        
        // Disable canary
        secure_vec.disable_canary();
        assert!(secure_vec.check_canary()); // Should still pass when disabled
        
        // Enable canary
        secure_vec.enable_canary();
        assert!(secure_vec.check_canary());
    }
}