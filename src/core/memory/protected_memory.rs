/*!
Protected memory implementation for the PQC protocol.

This module provides memory protection utilities that use mprotect (on Unix)
and VirtualProtect (on Windows) to make sensitive memory regions read-only
after initialization, preventing accidental or malicious modification.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::fmt;
use std::marker::PhantomData;
use crate::core::memory::zeroize::Zeroize;
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

// Determine the page size for the current platform
#[cfg(unix)]
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
fn get_page_size() -> usize {
    use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
    
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);
        system_info.dwPageSize as usize
    }
}

#[cfg(not(any(unix, windows)))]
fn get_page_size() -> usize {
    // Use a conservative estimate for unknown platforms
    4096
}

/// A memory region that can be made read-only to prevent tampering.
pub struct ProtectedMemory<T: Sized> {
    /// Pointer to the protected data
    data: *mut T,
    /// Buffer containing the data and padding to page boundaries
    buffer: ZeroizeOnDrop<Vec<u8>>,
    /// The protection state
    protected: bool,
    /// Size of a page on this system
    page_size: usize,
    /// Phantom data to track ownership of T
    _phantom: PhantomData<T>,
}

// Allow sending between threads if T is Send
unsafe impl<T: Sized + Send> Send for ProtectedMemory<T> {}
// Allow sharing between threads if T is Sync
unsafe impl<T: Sized + Sync> Sync for ProtectedMemory<T> {}

impl<T: Sized> ProtectedMemory<T> {
    /// Create a new protected memory region containing the given value.
    pub fn new(value: T) -> Self {
        let page_size = get_page_size();
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
            protected: false,
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
    
    /// Enable memory protection (make read-only).
    pub fn protect(&mut self) -> bool {
        if self.protected {
            return true; // Already protected
        }
        
        #[cfg(unix)]
        {
            use libc::{mprotect, PROT_READ};
            
            let page_base = self.get_page_base();
            let size = self.page_size;
            
            // Make the page read-only
            let result = unsafe { mprotect(page_base as *mut _, size, PROT_READ) };
            
            if result == 0 {
                self.protected = true;
                true
            } else {
                eprintln!("Failed to protect memory: errno={}", unsafe { *libc::__errno_location() });
                false
            }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READONLY;
            
            let page_base = self.get_page_base();
            let size = self.page_size;
            let mut old_protect = 0;
            
            // Make the page read-only
            let result = unsafe {
                VirtualProtect(
                    page_base as *mut _,
                    size,
                    PAGE_READONLY,
                    &mut old_protect
                )
            };
            
            if result != 0 {
                self.protected = true;
                true
            } else {
                eprintln!("Failed to protect memory: error={}", unsafe { winapi::um::errhandlingapi::GetLastError() });
                false
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            // Unsupported platform, just return false
            eprintln!("Memory protection not supported on this platform");
            false
        }
    }
    
    /// Disable memory protection (make writable).
    pub fn unprotect(&mut self) -> bool {
        if !self.protected {
            return true; // Already unprotected
        }
        
        #[cfg(unix)]
        {
            use libc::{mprotect, PROT_READ, PROT_WRITE};
            
            let page_base = self.get_page_base();
            let size = self.page_size;
            
            // Make the page readable and writable
            let result = unsafe { mprotect(page_base as *mut _, size, PROT_READ | PROT_WRITE) };
            
            if result == 0 {
                self.protected = false;
                true
            } else {
                eprintln!("Failed to unprotect memory: errno={}", unsafe { *libc::__errno_location() });
                false
            }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READWRITE;
            
            let page_base = self.get_page_base();
            let size = self.page_size;
            let mut old_protect = 0;
            
            // Make the page readable and writable
            let result = unsafe {
                VirtualProtect(
                    page_base as *mut _,
                    size,
                    PAGE_READWRITE,
                    &mut old_protect
                )
            };
            
            if result != 0 {
                self.protected = false;
                true
            } else {
                eprintln!("Failed to unprotect memory: error={}", unsafe { winapi::um::errhandlingapi::GetLastError() });
                false
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            // Unsupported platform, just return false
            eprintln!("Memory protection not supported on this platform");
            false
        }
    }
    
    /// Check if the memory is currently protected.
    pub fn is_protected(&self) -> bool {
        self.protected
    }
    
    /// Get a reference to the inner value.
    pub fn inner(&self) -> &T {
        unsafe { &*self.data }
    }
    
    /// Get a mutable reference to the inner value.
    /// This will automatically unprotect the memory if needed.
    pub fn inner_mut(&mut self) -> &mut T {
        // Unprotect if needed
        if self.protected {
            self.unprotect();
        }
        
        unsafe { &mut *self.data }
    }
    
    /// Consume the container and return the inner value
    pub fn into_inner(mut self) -> T {
        // Unprotect if needed
        if self.protected {
            self.unprotect();
        }
        
        // Read the value
        let value = unsafe { ptr::read(self.data) };
        
        // Prevent drop from running to avoid double-free
        std::mem::forget(self);
        
        value
    }
}

impl<T: Sized> Deref for ProtectedMemory<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<T: Sized> DerefMut for ProtectedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner_mut()
    }
}

impl<T: Sized> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        // Unprotect memory if it's protected
        if self.protected {
            self.unprotect();
        }
        
        // Explicitly drop the inner value
        unsafe {
            ptr::drop_in_place(self.data);
        }
        
        // Buffer will be zeroed by ZeroizeOnDrop
    }
}

impl<T: Sized + Clone> Clone for ProtectedMemory<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner().clone())
    }
}

impl<T: Sized + fmt::Debug> fmt::Debug for ProtectedMemory<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtectedMemory({:?})", self.inner())
    }
}

impl<T: Sized + Zeroize> Zeroize for ProtectedMemory<T> {
    fn zeroize(&mut self) {
        // Unprotect memory if it's protected
        if self.protected {
            self.unprotect();
        }
        
        // Zeroize the inner value
        unsafe {
            (*self.data).zeroize();
        }
    }
}

// Common type aliases
pub type ProtectedBytes = ProtectedMemory<Vec<u8>>;
pub type ProtectedKey32 = ProtectedMemory<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protected_memory_basics() {
        let value = [1u8, 2, 3, 4, 5];
        let mut protected = ProtectedMemory::new(value);
        
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
        let mut protected = ProtectedMemory::new([1u8, 2, 3]);
        
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
        let mut protected = ProtectedMemory::new([1u8, 2, 3]);
        protected.protect();
        
        // Extract the value
        let value = protected.into_inner();
        assert_eq!(value, [1, 2, 3]);
        
        // The destructor should not run now, as we used into_inner
    }
    
    #[test]
    fn test_zeroize() {
        let mut protected = ProtectedMemory::new([1u8, 2, 3]);
        protected.protect();
        
        // Zeroize the memory
        protected.zeroize();
        
        // Should no longer be protected
        assert!(!protected.is_protected());
        
        // Value should be zeroed
        assert_eq!(*protected, [0, 0, 0]);
    }
}