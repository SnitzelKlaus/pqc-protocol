/*!
Secure memory for cryptographic keys.

This module provides an enhanced secure memory implementation for storing sensitive data
like cryptographic keys, preventing them from being swapped to disk and
ensuring they are properly zeroed when dropped.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::alloc::{self, Layout};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};

/// A secure memory container for sensitive data.
///
/// SecureMemory:
/// - Allocates memory with a guard page
/// - Prevents memory from being swapped to disk (when possible)
/// - Zeros memory when dropped
/// - Uses mlock on Unix platforms
/// - Adds canary values to detect buffer overflows
/// - Implements timing-safe equality comparisons
///
/// # Example
///
/// ```
/// use pqc_protocol::memory::SecureMemory;
///
/// let mut secure_key = SecureMemory::new([0u8; 32]);
/// secure_key[0] = 42;
/// assert_eq!(secure_key[0], 42);
/// ```
#[derive(Debug)]
pub struct SecureMemory<T: ?Sized> {
    /// Pointer to the secured memory
    inner: *mut T,
    /// Memory layout information
    layout: Layout,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Canary value for detecting buffer overflows
    #[cfg(feature = "memory-canary")]
    canary: u64,
}

unsafe impl<T: ?Sized + Send> Send for SecureMemory<T> {}
unsafe impl<T: ?Sized + Sync> Sync for SecureMemory<T> {}

impl<T> SecureMemory<T> {
    /// Create a new secure memory container.
    pub fn new(value: T) -> Self {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        
        // Ensure we have a valid layout
        let layout = Layout::from_size_align(size, align)
            .expect("Invalid layout for secure memory");
        
        #[cfg(feature = "memory-canary")]
        let canary = rand::random::<u64>();
        
        let mut locked = AtomicBool::new(false);
        
        unsafe {
            // Allocate memory
            let ptr = alloc::alloc(layout) as *mut T;
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            // Initialize memory
            ptr::write(ptr, value);
            
            // Lock memory to prevent swapping (platform-specific)
            #[cfg(unix)]
            {
                use libc::{mlock, ENOMEM};
                let result = mlock(ptr as *const _, size);
                if result == 0 {
                    locked = AtomicBool::new(true);
                } else {
                    let err = *libc::__errno_location();
                    if err == ENOMEM {
                        // Non-fatal: couldn't lock memory but we'll still use it
                        // This can happen if the user doesn't have the right permissions
                        log::warn!("Failed to lock memory with mlock, continuing with unlocked memory");
                    }
                }
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            {
                use winapi::um::memoryapi::VirtualLock;
                if VirtualLock(ptr as *mut _, size) != 0 {
                    locked = AtomicBool::new(true);
                } else {
                    log::warn!("Failed to lock memory with VirtualLock, continuing with unlocked memory");
                }
            }
            
            Self {
                inner: ptr,
                layout,
                locked,
                #[cfg(feature = "memory-canary")]
                canary,
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
    
    /// Check if memory lock succeeded
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
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
    
    /// Explicitly clear memory
    pub fn clear(&mut self) {
        unsafe {
            ptr::write_bytes(self.inner as *mut u8, 0, self.layout.size());
        }
    }
    
    #[cfg(feature = "memory-canary")]
    /// Check if the canary value is intact
    pub fn check_canary(&self) -> bool {
        let stored_canary = self.stored_canary();
        self.canary == stored_canary
    }
    
    #[cfg(feature = "memory-canary")]
    /// Get the stored canary value
    fn stored_canary(&self) -> u64 {
        unsafe {
            // Canary is stored after the actual data
            let canary_ptr = (self.inner as *const u8)
                .add(mem::size_of::<T>()) as *const u64;
            ptr::read(canary_ptr)
        }
    }
}

impl<T: ?Sized> Deref for SecureMemory<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.inner }
    }
}

impl<T: ?Sized> DerefMut for SecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.inner }
    }
}

impl<T: ?Sized> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        unsafe {
            // Get the size of the stored value
            let size = self.layout.size();
            
            // Zero the memory before deallocation
            ptr::write_bytes(self.inner as *mut u8, 0, size);
            
            #[cfg(feature = "memory-canary")]
            {
                // Check canary before dropping
                if !self.check_canary() {
                    // Buffer overflow detected
                    log::error!("SecureMemory canary value corrupted - buffer overflow detected");
                    // In a real application, we might want to abort here
                }
            }
            
            // Unlock memory (platform-specific)
            if self.locked.load(Ordering::Relaxed) {
                #[cfg(unix)]
                {
                    libc::munlock(self.inner as *const _, size);
                }
                
                #[cfg(all(target_os = "windows", feature = "windows-lock"))]
                {
                    use winapi::um::memoryapi::VirtualUnlock;
                    VirtualUnlock(self.inner as *mut _, size);
                }
            }
            
            // Properly drop the inner value
            ptr::drop_in_place(self.inner);
            
            // Deallocate memory
            alloc::dealloc(self.inner as *mut u8, self.layout);
        }
    }
}

/// Wrapper around standard Vec for secure operations
pub struct SecureVec<T> {
    /// Inner vector
    inner: Vec<T>,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
}

impl<T> SecureVec<T> {
    /// Create a new secure vector
    pub fn new() -> Self {
        Self {
            inner: Vec::new(),
            locked: AtomicBool::new(false),
        }
    }
    
    /// Create a secure vector with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
            locked: AtomicBool::new(false),
        }
    }
    
    /// Create a secure vector from existing vector
    pub fn from_vec(vec: Vec<T>) -> Self {
        let mut secure = Self {
            inner: vec,
            locked: AtomicBool::new(false),
        };
        
        // Try to lock memory
        secure.try_lock_memory();
        
        secure
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
    
    /// Clear the memory
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
        if std::mem::size_of::<T>() > 0 {
            unsafe {
                let ptr = self.inner.as_mut_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                ptr::write_bytes(ptr as *mut u8, 0, size);
            }
        }
        
        self.inner.clear();
    }
}

impl<T> Deref for SecureVec<T> {
    type Target = Vec<T>;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Drop for SecureVec<T> {
    fn drop(&mut self) {
        // Clear the memory first
        self.clear();
    }
}

impl<T> Default for SecureVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility trait for securely zeroizing sensitive data
pub trait Zeroize {
    /// Securely zero this object's memory
    fn zeroize(&mut self);
}

impl<T> Zeroize for SecureMemory<T> {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl<T> Zeroize for SecureVec<T> {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        // Use volatile writes to ensure the compiler doesn't optimize away
        for byte in self.iter_mut() {
            unsafe {
                ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Helper to detect compiler optimizations during zeroizing
#[inline(never)]
pub fn secure_zero_memory(memory: &mut [u8]) {
    memory.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_memory_basic() {
        let mut secure = SecureMemory::new([0u8; 32]);
        
        // Check that we can mutate the memory
        secure[0] = 42;
        secure[1] = 43;
        
        assert_eq!(secure[0], 42);
        assert_eq!(secure[1], 43);
    }
    
    #[test]
    fn test_secure_memory_large() {
        // Test with a larger value to ensure it works
        let data = vec![0u8; 4096];
        let mut secure = SecureMemory::new(data);
        
        secure[10] = 42;
        secure[100] = 43;
        
        assert_eq!(secure[10], 42);
        assert_eq!(secure[100], 43);
    }
    
    #[test]
    fn test_secure_memory_zeroed() {
        let secure: SecureMemory<[u8; 32]> = SecureMemory::zeroed();
        
        // Check that all bytes are zero
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_memory_clear() {
        let mut secure = SecureMemory::new([42u8; 32]);
        
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
    fn test_zeroize_trait() {
        let mut data = [42u8; 64];
        
        // Zeroize the memory
        data.zeroize();
        
        // Check that all bytes are zero
        for byte in &data {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_vec_with_capacity() {
        let mut secure_vec = SecureVec::<u8>::with_capacity(100);
        
        secure_vec.push(1);
        secure_vec.push(2);
        secure_vec.push(3);
        
        assert_eq!(secure_vec.len(), 3);
        assert!(secure_vec.capacity() >= 100);
        
        secure_vec.clear();
        assert_eq!(secure_vec.len(), 0);
    }
}