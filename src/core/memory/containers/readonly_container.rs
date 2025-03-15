/*!
Read-only protected memory implementation for the PQC protocol.

This module provides memory containers that can be made read-only through 
OS mechanisms like mprotect/VirtualProtect to prevent accidental or 
malicious modification.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::memory::traits::zeroize::Zeroize;
use crate::core::memory::utils::zeroize_on_drop::ZeroizeOnDrop;
use crate::core::memory::platform::get_platform_impl;
use crate::core::memory::traits::protection::MemoryProtection;
use crate::core::memory::error::{Error, Result};

/// A memory container that can be made read-only to prevent tampering.
pub struct ReadOnlyContainer<T: Sized> {
    /// Pointer to the protected data
    data: *mut T,
    /// Buffer containing the data and padding to page boundaries
    buffer: ZeroizeOnDrop<Vec<u8>>,
    /// The protection state
    protected: AtomicBool,
    /// Size of a page on this system
    page_size: usize,
    /// Phantom data to track ownership of T
    _phantom: PhantomData<T>,
}

// Allow sending between threads if T is Send
unsafe impl<T: Sized + Send> Send for ReadOnlyContainer<T> {}
// Allow sharing between threads if T is Sync
unsafe impl<T: Sized + Sync> Sync for ReadOnlyContainer<T> {}

impl<T: Sized> ReadOnlyContainer<T> {
    /// Create a new read-only memory container with the given value.
    pub fn new(value: T) -> Self {
        let platform = get_platform_impl();
        let page_size = platform.page_size();
        let size = std::mem::size_of::<T>();
        
        // Allocate a buffer large enough to hold T, aligned to page boundaries
        let buffer_size = (size + page_size * 2 - 1) & !(page_size - 1);
        let mut buffer = vec![0u8; buffer_size];
        
        // Calculate address for properly aligned placement
        let buffer_addr = buffer.as_ptr() as usize;
        let aligned_addr = (buffer_addr + page_size - 1) & !(page_size - 1);
        let offset = aligned_addr - buffer_addr;
        
        // Place the value at the aligned address
        let data_ptr = unsafe { buffer.as_mut_ptr().add(offset) as *mut T };
        unsafe { ptr::write(data_ptr, value) };
        
        Self {
            data: data_ptr,
            buffer: ZeroizeOnDrop::new(buffer),
            protected: AtomicBool::new(false),
            page_size,
            _phantom: PhantomData,
        }
    }
    
    /// Get the base address of the memory page containing the data.
    fn get_page_base(&self) -> *mut u8 {
        let addr = self.data as usize;
        let page_base = addr & !(self.page_size - 1);
        page_base as *mut u8
    }
    
    /// Is the memory currently protected (read-only)?
    pub fn is_protected(&self) -> bool {
        self.protected.load(Ordering::Relaxed)
    }
    
    /// Enable memory protection (make read-only).
    pub fn protect(&self) -> bool {
        if self.is_protected() {
            return true; // Already protected
        }
        
        let platform = get_platform_impl();
        let result = platform.protect_memory_readonly(self.get_page_base(), self.page_size);
        
        match result {
            Ok(()) => {
                self.protected.store(true, Ordering::Relaxed);
                true
            },
            Err(e) => {
                eprintln!("Failed to protect memory: {}", e);
                false
            }
        }
    }
    
    /// Disable memory protection (make writable).
    pub fn unprotect(&self) -> bool {
        if !self.is_protected() {
            return true; // Already unprotected
        }
        
        let platform = get_platform_impl();
        let result = platform.protect_memory_readwrite(self.get_page_base(), self.page_size);
        
        match result {
            Ok(()) => {
                self.protected.store(false, Ordering::Relaxed);
                true
            },
            Err(e) => {
                eprintln!("Failed to unprotect memory: {}", e);
                false
            }
        }
    }
    
    /// Get a reference to the inner value.
    pub fn inner(&self) -> &T {
        unsafe { &*self.data }
    }
    
    /// Get a mutable reference to the inner value.
    /// This will automatically unprotect the memory if needed.
    pub fn inner_mut(&mut self) -> &mut T {
        // Unprotect if needed
        if self.is_protected() {
            self.unprotect();
        }
        
        unsafe { &mut *self.data }
    }
    
    /// Consume the container and return the inner value
    pub fn into_inner(mut self) -> T {
        // Unprotect if needed
        if self.is_protected() {
            self.unprotect();
        }
        
        // Read the value
        let value = unsafe { ptr::read(self.data) };
        
        // Prevent drop from running to avoid double-free
        std::mem::forget(self);
        
        value
    }
}

impl<T: Sized> MemoryProtection for ReadOnlyContainer<T> {
    /// Lock the memory to prevent swapping
    fn lock_memory(&mut self) -> Result<()> {
        let platform = get_platform_impl();
        platform.lock_memory(self.get_page_base(), self.page_size)
    }
    
    /// Unlock previously locked memory
    fn unlock_memory(&mut self) -> Result<()> {
        let platform = get_platform_impl();
        platform.unlock_memory(self.get_page_base(), self.page_size)
    }
    
    /// Check if memory is locked (always returns false - we don't track this state)
    fn is_memory_locked(&self) -> bool {
        false // We don't track this state
    }
    
    /// Make memory read-only
    fn make_read_only(&mut self) -> Result<()> {
        if self.protect() {
            Ok(())
        } else {
            Err(Error::ProtectionFailed("Failed to make memory read-only".to_string()))
        }
    }
    
    /// Make memory writable
    fn make_writable(&mut self) -> Result<()> {
        if self.unprotect() {
            Ok(())
        } else {
            Err(Error::ProtectionFailed("Failed to make memory writable".to_string()))
        }
    }
    
    /// Check if memory is read-only
    fn is_read_only(&self) -> bool {
        self.is_protected()
    }
    
    /// Check for buffer overflows (not implemented for this type)
    fn check_integrity(&self) -> Result<()> {
        Ok(()) // No integrity checking for this type
    }
    
    /// Clear memory by filling with zeros
    fn clear(&mut self) -> Result<()> {
        self.zeroize();
        Ok(())
    }
}

impl<T: Sized> Deref for ReadOnlyContainer<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<T: Sized> DerefMut for ReadOnlyContainer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner_mut()
    }
}

impl<T: Sized> Drop for ReadOnlyContainer<T> {
    fn drop(&mut self) {
        // Unprotect memory if it's protected
        if self.is_protected() {
            self.unprotect();
        }
        
        // Explicitly drop the inner value
        unsafe {
            ptr::drop_in_place(self.data);
        }
        
        // Buffer will be zeroed by ZeroizeOnDrop
    }
}

impl<T: Sized + Clone> Clone for ReadOnlyContainer<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner().clone())
    }
}

impl<T: Sized + fmt::Debug> fmt::Debug for ReadOnlyContainer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadOnlyContainer")
            .field("value", &self.inner())
            .field("protected", &self.is_protected())
            .finish()
    }
}

impl<T: Sized + Zeroize> Zeroize for ReadOnlyContainer<T> {
    fn zeroize(&mut self) {
        // Unprotect memory if it's protected
        if self.is_protected() {
            self.unprotect();
        }
        
        // Zeroize the inner value
        unsafe {
            (*self.data).zeroize();
        }
    }
}

// Common type aliases
pub type ProtectedBytes = ReadOnlyContainer<Vec<u8>>;
pub type ProtectedKey32 = ReadOnlyContainer<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_readonly_container_basics() {
        let value = [1u8, 2, 3, 4, 5];
        let mut protected = ReadOnlyContainer::new(value);
        
        // Check initial state
        assert!(!protected.is_protected());
        assert_eq!(*protected, [1, 2, 3, 4, 5]);
        
        // Protect memory
        if protected.protect() {
            assert!(protected.is_protected());
            
            // Can still read the value
            assert_eq!(*protected, [1, 2, 3, 4, 5]);
            
            // Unprotect to modify
            protected.unprotect();
            assert!(!protected.is_protected());
            
            // Now we can modify
            protected[0] = 10;
            assert_eq!(*protected, [10, 2, 3, 4, 5]);
        }
    }
    
    #[test]
    fn test_automatic_unprotect() {
        let mut protected = ReadOnlyContainer::new([1u8, 2, 3]);
        
        // Protect memory
        if protected.protect() {
            // This should automatically unprotect
            *protected.inner_mut() = [4, 5, 6];
            
            // Should no longer be protected
            assert!(!protected.is_protected());
            assert_eq!(*protected, [4, 5, 6]);
        }
    }
    
    #[test]
    fn test_into_inner() {
        let mut protected = ReadOnlyContainer::new([1u8, 2, 3]);
        protected.protect();
        
        // Extract the value
        let value = protected.into_inner();
        assert_eq!(value, [1, 2, 3]);
        
        // The destructor should not run now, as we used into_inner
    }
    
    #[test]
    fn test_zeroize() {
        let mut protected = ReadOnlyContainer::new([1u8, 2, 3]);
        protected.protect();
        
        // Zeroize the memory
        protected.zeroize();
        
        // Should no longer be protected
        assert!(!protected.is_protected());
        
        // Value should be zeroed
        assert_eq!(*protected, [0, 0, 0]);
    }
    
    #[test]
    fn test_memory_protection() {
        let mut protected = ReadOnlyContainer::new([1u8, 2, 3]);
        
        // Test memory protection interface
        assert!(!protected.is_read_only());
        
        let _ = protected.make_read_only();
        assert!(protected.is_read_only());
        
        let _ = protected.make_writable();
        assert!(!protected.is_read_only());
        
        // Test clearing
        let _ = protected.clear();
        assert_eq!(*protected, [0, 0, 0]);
    }
}