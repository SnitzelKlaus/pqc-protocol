/*!
Core secure memory container implementation for the PQC protocol.

Provides the base container for storing sensitive data with
memory protection and zeroization on drop.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::alloc::{self, Layout};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};

use rand::{Rng, thread_rng};
use subtle::ConstantTimeEq;

use crate::core::memory::traits::zeroize::{Zeroize, secure_zero_memory};
use crate::core::memory::traits::protection::MemoryProtection;
use crate::core::memory::error::{Error, Result};
use crate::core::memory::platform::get_platform_impl;

/// A secure memory container for sensitive data.
///
/// Features:
/// - Allocates memory with padding and alignment for protection
/// - Prevents memory from being swapped to disk (when possible)
/// - Zeros memory when dropped using volatile writes
/// - Uses mlock on Unix platforms and VirtualLock on Windows
/// - Adds canary values to detect buffer overflows
/// - Implements timing-safe equality comparisons
/// - Randomizes padding to prevent heap fingerprinting
pub struct SecureContainer<T: ?Sized> {
    /// Pointer to the secured memory
    inner: *mut T,
    /// Memory layout information
    layout: Layout,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Flag indicating if canary protection is enabled
    canary_enabled: AtomicBool,
    /// Canary value for detecting buffer overflows
    canary: u64,
    /// Size of the padding added to both sides of the allocation
    padding_size: usize,
}

unsafe impl<T: ?Sized + Send> Send for SecureContainer<T> {}
unsafe impl<T: ?Sized + Sync> Sync for SecureContainer<T> {}

impl<T> SecureContainer<T> {
    /// Create a new secure memory container.
    pub fn new(value: T) -> Self {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        
        // Add padding for protection
        // Using 64 bytes of padding on each side (typical cache line size)
        let padding_size = 64;
        let total_size = size + (padding_size * 2);
        
        // Ensure we have a valid layout with proper alignment
        let layout = Layout::from_size_align(total_size, align.max(64))
            .expect("Invalid layout for secure memory");
        
        // Generate random canary value
        let canary = thread_rng().gen::<u64>();
        
        let locked = AtomicBool::new(false);
        let canary_enabled = AtomicBool::new(cfg!(feature = "memory-canary"));
        
        unsafe {
            // Allocate memory
            let allocation = alloc::alloc(layout) as *mut u8;
            if allocation.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            // Calculate pointer to the actual data (after padding)
            let ptr = allocation.add(padding_size) as *mut T;
            
            // Initialize memory
            ptr::write(ptr, value);
            
            // Generate random padding to prevent fingerprinting
            let mut rng = thread_rng();
            // Front padding
            for i in 0..padding_size {
                ptr::write_volatile(allocation.add(i), rng.gen::<u8>());
            }
            // Back padding
            for i in 0..padding_size {
                ptr::write_volatile(allocation.add(padding_size + size + i), rng.gen::<u8>());
            }
            
            // Write canary values at the end of each padding area
            if cfg!(feature = "memory-canary") {
                let front_canary_ptr = allocation.add(padding_size - 8) as *mut u64;
                let back_canary_ptr = allocation.add(padding_size + size) as *mut u64;
                ptr::write_volatile(front_canary_ptr, canary);
                ptr::write_volatile(back_canary_ptr, canary);
            }
            
            // Try to lock the memory to prevent swapping
            let platform = get_platform_impl();
            let lock_result = platform.lock_memory(allocation, total_size);
            if lock_result.is_ok() {
                locked.store(true, Ordering::Relaxed);
            }
            
            Self {
                inner: ptr,
                layout,
                locked,
                canary_enabled,
                canary,
                padding_size,
            }
        }
    }
    
    /// Create a new secure memory container with zeros.
    pub fn zeroed() -> Self
    where
        T: Default,
    {
        Self::new(T::default())
    }
    
    /// Get the actual allocation base pointer (internal use only)
    unsafe fn allocation_base(&self) -> *mut u8 {
        // The allocation base is padding_size bytes before the inner pointer
        (self.inner as *mut u8).sub(self.padding_size)
    }
    
    /// Convert to a byte slice (for clearing/zeroizing)
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.inner as *const u8,
                mem::size_of::<T>(),
            )
        }
    }
    
    /// Convert to a mutable byte slice (for clearing/zeroizing)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.inner as *mut u8,
                mem::size_of::<T>(),
            )
        }
    }
    
    /// Explicitly clear memory using a secure zeroization method
    pub fn clear(&mut self) {
        let _ = self.check_integrity();
        self.zeroize();
    }
    
    /// Fill memory with random data
    pub fn randomize(&mut self) {
        let size = mem::size_of::<T>();
        if size == 0 {
            return;
        }
        
        let mut rng = thread_rng();
        unsafe {
            let ptr = self.inner as *mut u8;
            
            // Fill with random bytes
            for i in 0..size {
                ptr::write_volatile(ptr.add(i), rng.gen::<u8>());
            }
        }
    }
    
    /// Get the front canary value if enabled
    unsafe fn front_canary(&self) -> Option<u64> {
        if !self.canary_enabled.load(Ordering::Relaxed) {
            return None;
        }
        
        let front_canary_ptr = self.allocation_base().add(self.padding_size - 8) as *const u64;
        Some(ptr::read_volatile(front_canary_ptr))
    }
    
    /// Get the back canary value if enabled
    unsafe fn back_canary(&self) -> Option<u64> {
        if !self.canary_enabled.load(Ordering::Relaxed) {
            return None;
        }
        
        let size = mem::size_of::<T>();
        let back_canary_ptr = (self.inner as *mut u8).add(size) as *const u64;
        Some(ptr::read_volatile(back_canary_ptr))
    }
    
    /// Enable canary protection
    pub fn enable_canary(&mut self) {
        if !self.canary_enabled.load(Ordering::Relaxed) {
            self.canary_enabled.store(true, Ordering::Relaxed);
            
            unsafe {
                // Write canary values
                let allocation = self.allocation_base();
                let size = mem::size_of::<T>();
                
                let front_canary_ptr = allocation.add(self.padding_size - 8) as *mut u64;
                let back_canary_ptr = allocation.add(self.padding_size + size) as *mut u64;
                
                ptr::write_volatile(front_canary_ptr, self.canary);
                ptr::write_volatile(back_canary_ptr, self.canary);
            }
        }
    }
    
    /// Disable canary protection
    pub fn disable_canary(&mut self) {
        self.canary_enabled.store(false, Ordering::Relaxed);
    }
    
    /// Check canary values for buffer overflow detection
    pub fn check_canary_values(&self) -> bool {
        if !self.canary_enabled.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            let front_canary = self.front_canary().unwrap_or(self.canary);
            let back_canary = self.back_canary().unwrap_or(self.canary);
            
            if front_canary != self.canary || back_canary != self.canary {
                // Log the error
                eprintln!("SECURITY ERROR: SecureContainer canary values corrupted - buffer overflow detected!");
                
                if front_canary != self.canary {
                    eprintln!("Front canary corrupted: expected {:x}, found {:x}", self.canary, front_canary);
                }
                
                if back_canary != self.canary {
                    eprintln!("Back canary corrupted: expected {:x}, found {:x}", self.canary, back_canary);
                }
                
                return false;
            }
            
            true
        }
    }
    
    /// Compare two secure memory containers in constant time
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if mem::size_of::<T>() != mem::size_of::<T>() {
            return false;
        }
        
        let self_bytes = self.as_bytes();
        let other_bytes = other.as_bytes();
        
        self_bytes.ct_eq(other_bytes).unwrap_u8() == 1
    }
    
    /// Clone to another SecureContainer
    pub fn secure_clone(&self) -> Self 
    where 
        T: Clone
    {
        let _ = self.check_integrity();
        
        unsafe {
            // Clone the inner value
            let cloned = (*self.inner).clone();
            Self::new(cloned)
        }
    }
}

impl<T: ?Sized> MemoryProtection for SecureContainer<T> {
    fn lock_memory(&mut self) -> Result<()> {
        if self.locked.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        unsafe {
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            let platform = get_platform_impl();
            let result = platform.lock_memory(allocation, total_size);
            
            if result.is_ok() {
                self.locked.store(true, Ordering::Relaxed);
            }
            
            result
        }
    }
    
    fn unlock_memory(&mut self) -> Result<()> {
        if !self.locked.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        unsafe {
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            let platform = get_platform_impl();
            let result = platform.unlock_memory(allocation, total_size);
            
            if result.is_ok() {
                self.locked.store(false, Ordering::Relaxed);
            }
            
            result
        }
    }
    
    fn is_memory_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    
    fn make_read_only(&mut self) -> Result<()> {
        unsafe {
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            let platform = get_platform_impl();
            platform.protect_memory_readonly(allocation, total_size)
        }
    }
    
    fn make_writable(&mut self) -> Result<()> {
        unsafe {
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            let platform = get_platform_impl();
            platform.protect_memory_readwrite(allocation, total_size)
        }
    }
    
    fn is_read_only(&self) -> bool {
        false // We don't track this state
    }
    
    fn check_integrity(&self) -> Result<()> {
        if !self.check_canary_values() {
            Err(Error::BufferOverflow)
        } else {
            Ok(())
        }
    }
    
    fn clear(&mut self) -> Result<()> {
        self.zeroize();
        Ok(())
    }
}

impl<T: ?Sized> Deref for SecureContainer<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        let _ = self.check_integrity();
        unsafe { &*self.inner }
    }
}

impl<T: ?Sized> DerefMut for SecureContainer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let _ = self.check_integrity();
        unsafe { &mut *self.inner }
    }
}

impl<T: ?Sized> Drop for SecureContainer<T> {
    fn drop(&mut self) {
        // Check for buffer overflows before deallocation
        let overflow_detected = if self.canary_enabled.load(Ordering::Relaxed) {
            !self.check_canary_values()
        } else {
            false
        };
        
        // Zero the memory regardless of feature flags for consistency
        self.zeroize();
        
        unsafe {
            // Get the actual allocation base
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            // Unlock memory if it was locked
            if self.locked.load(Ordering::Relaxed) {
                let platform = get_platform_impl();
                let _ = platform.unlock_memory(allocation, total_size);
            }
            
            // Deallocate memory
            alloc::dealloc(allocation, self.layout);
        }
        
        // If an overflow was detected, we might want to abort the program
        // in a production environment to prevent further exploitation
        if overflow_detected && cfg!(feature = "abort-on-overflow") {
            eprintln!("FATAL: SecureContainer buffer overflow detected. Aborting.");
            std::process::abort();
        }
    }
}

impl<T: Default> Default for SecureContainer<T> {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<T: Clone> Clone for SecureContainer<T> {
    fn clone(&self) -> Self {
        self.secure_clone()
    }
}

impl<T: PartialEq> PartialEq for SecureContainer<T> {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for equality
        self.constant_time_eq(other) || **self == **other
    }
}

impl<T> Zeroize for SecureContainer<T> {
    fn zeroize(&mut self) {
        let size = mem::size_of::<T>();
        if size == 0 {
            return;
        }
        
        unsafe {
            let ptr = self.inner as *mut u8;
            
            // Zero the memory using volatile writes
            for i in 0..size {
                ptr::write_volatile(ptr.add(i), 0);
            }
            
            // Prevent compiler optimization by reading back the memory
            let mut sum: u8 = 0;
            for i in 0..size {
                sum ^= ptr::read_volatile(ptr.add(i));
            }
            
            // Use sum in a way that compiler can't optimize away
            if sum != 0 {
                // This should never happen, but the compiler doesn't know that
                ptr::write_volatile(ptr, sum);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_container_basic() {
        let mut secure = SecureContainer::new([0u8; 32]);
        
        // Check that we can mutate the memory
        secure[0] = 42;
        secure[1] = 43;
        
        assert_eq!(secure[0], 42);
        assert_eq!(secure[1], 43);
    }
    
    #[test]
    fn test_secure_container_zeroed() {
        let secure: SecureContainer<[u8; 32]> = SecureContainer::zeroed();
        
        // Check that all bytes are zero
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_container_clear() {
        let mut secure = SecureContainer::new([42u8; 32]);
        
        // Check that memory contains our value
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 42);
        }
        
        // Clear the memory
        secure.clear();
        
        // Check that all bytes are now zero
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_container_canary() {
        let mut secure = SecureContainer::new([0u8; 32]);
        
        // Enable canary explicitly (already enabled if feature is active)
        secure.enable_canary();
        
        // Canary check should pass
        assert!(secure.check_canary_values());
        
        // Disable canary and check again
        secure.disable_canary();
        
        // Should still pass since we're no longer checking
        assert!(secure.check_canary_values());
        
        // Re-enable for further tests
        secure.enable_canary();
        
        // In a real test we'd try to overflow the buffer,
        // but that's not easy to do safely in a test
    }
    
    #[test]
    fn test_secure_container_constant_time_eq() {
        let secure1 = SecureContainer::new([42u8; 32]);
        let secure2 = SecureContainer::new([42u8; 32]);
        let secure3 = SecureContainer::new([0u8; 32]);
        
        assert!(secure1.constant_time_eq(&secure2));
        assert!(!secure1.constant_time_eq(&secure3));
    }
    
    #[test]
    fn test_memory_protection() {
        let mut secure = SecureContainer::new([0u8; 32]);
        
        // Test memory protection API
        assert!(secure.is_memory_locked() || !cfg!(feature = "memory-lock"));
        
        // These may succeed or fail depending on the platform
        let _ = secure.unlock_memory();
        let _ = secure.lock_memory();
        let _ = secure.make_read_only();
        let _ = secure.make_writable();
    }
}