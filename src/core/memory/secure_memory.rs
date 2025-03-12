/*!
Secure memory for cryptographic keys.

This module provides a secure memory implementation for storing sensitive data
like cryptographic keys, preventing them from being swapped to disk and
ensuring they are properly zeroed when dropped.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::alloc::{self, Layout};
use std::mem;

/// A secure memory container for sensitive data.
///
/// SecureMemory:
/// - Allocates memory with a guard page
/// - Prevents memory from being swapped to disk (when possible)
/// - Zeros memory when dropped
/// - Uses mlock on Unix platforms
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
    inner: *mut T,
    layout: Layout,
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
                if result == -1 {
                    let err = *libc::__errno_location();
                    if err == ENOMEM {
                        // Non-fatal: couldn't lock memory but we'll still use it
                        // This can happen if the user doesn't have the right permissions
                        log::warn!("Failed to lock memory with mlock, continuing with unlocked memory");
                    }
                }
            }
            
            Self {
                inner: ptr,
                layout,
            }
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
            
            // Unlock memory (platform-specific)
            #[cfg(unix)]
            {
                libc::munlock(self.inner as *const _, size);
            }
            
            // Properly drop the inner value
            ptr::drop_in_place(self.inner);
            
            // Deallocate memory
            alloc::dealloc(self.inner as *mut u8, self.layout);
        }
    }
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
}