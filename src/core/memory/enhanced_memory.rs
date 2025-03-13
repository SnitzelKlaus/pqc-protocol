/*!
Enhanced secure memory implementations for the PQC protocol.

This module provides advanced secure memory implementations with
additional protections like read-only memory when not in use.
*/

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use super::secure_memory::SecureMemory;
use super::zeroize::Zeroize;

/// Advanced secure memory container with additional protection mechanisms.
/// This version uses mprotect/VirtualProtect to create read-only pages when not in use.
/// Available with the "memory-enhanced" feature
#[cfg(feature = "memory-enhanced")]
pub struct EnhancedSecureMemory<T: Sized> {
    /// The secure memory container
    memory: SecureMemory<T>,
    /// Whether the memory is currently read-only
    read_only: AtomicBool,
    /// Page size for memory protection
    page_size: usize,
}

#[cfg(all(feature = "memory-enhanced", unix))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        use libc::{sysconf, _SC_PAGESIZE};
        
        // Get the system page size
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size,
        }
    }
    
    /// Make the memory read-only
    pub fn make_read_only(&self) -> bool {
        if self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use libc::{mprotect, PROT_READ};
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it read-only
            let result = mprotect(page_addr as *mut _, total_size, PROT_READ);
            
            if result == 0 {
                self.read_only.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Make the memory writable
    pub fn make_writable(&self) -> bool {
        if !self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use libc::{mprotect, PROT_READ, PROT_WRITE};
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it writable
            let result = mprotect(page_addr as *mut _, total_size, PROT_READ | PROT_WRITE);
            
            if result == 0 {
                self.read_only.store(false, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably (automatically makes it writable first)
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        // Ensure memory is writable
        self.make_writable();
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

/// Implementation for Windows systems with enhanced memory protection
#[cfg(all(feature = "memory-enhanced", target_os = "windows", feature = "windows-compat"))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        
        // Get the system page size
        let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        let page_size = sys_info.dwPageSize as usize;
        
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size,
        }
    }
    
    /// Make the memory read-only
    pub fn make_read_only(&self) -> bool {
        if self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READONLY;
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it read-only
            let mut old_protect = 0;
            let result = VirtualProtect(
                page_addr as *mut _,
                total_size,
                PAGE_READONLY,
                &mut old_protect
            );
            
            if result != 0 {
                self.read_only.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Make the memory writable
    pub fn make_writable(&self) -> bool {
        if !self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READWRITE;
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it writable
            let mut old_protect = 0;
            let result = VirtualProtect(
                page_addr as *mut _,
                total_size,
                PAGE_READWRITE,
                &mut old_protect
            );
            
            if result != 0 {
                self.read_only.store(false, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably (automatically makes it writable first)
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        // Ensure memory is writable
        self.make_writable();
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

/// Implementation for WebAssembly targets
/// In WASM, we can't do traditional memory locking, but we provide a compatible API
#[cfg(all(feature = "memory-enhanced", feature = "wasm-compat"))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size: 4096, // Default page size, not actually used
        }
    }
    
    /// Make the memory read-only (not fully supported in WASM)
    pub fn make_read_only(&self) -> bool {
        // In WASM, we can't actually protect memory, but we simulate the API
        self.read_only.store(true, Ordering::Relaxed);
        true
    }
    
    /// Make the memory writable (not fully supported in WASM)
    pub fn make_writable(&self) -> bool {
        // In WASM, we can't actually protect memory, but we simulate the API
        self.read_only.store(false, Ordering::Relaxed);
        true
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

// Implement common traits for EnhancedSecureMemory regardless of platform
#[cfg(feature = "memory-enhanced")]
impl<T: Sized + Default> Default for EnhancedSecureMemory<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "memory-enhanced")]
impl<T: Sized> Deref for EnhancedSecureMemory<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

#[cfg(feature = "memory-enhanced")]
impl<T: Sized> DerefMut for EnhancedSecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Ensure memory is writable before mutating
        self.make_writable();
        &mut *self.memory
    }
}

#[cfg(feature = "memory-enhanced")]
impl<T: Sized> Drop for EnhancedSecureMemory<T> {
    fn drop(&mut self) {
        // Make memory writable for proper cleanup
        self.make_writable();
        // Drop will be called on self.memory automatically
    }
}

#[cfg(feature = "memory-enhanced")]
impl<T: Sized> Zeroize for EnhancedSecureMemory<T> {
    fn zeroize(&mut self) {
        // Ensure memory is writable before zeroizing
        self.make_writable();
        self.memory.zeroize();
    }
}

#[cfg(all(test, feature = "memory-enhanced"))]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_secure_memory() {
        let mut enhanced = EnhancedSecureMemory::new([0u8; 32]);
        
        // Should start as writable
        assert!(!enhanced.is_read_only());
        
        // Set some values
        enhanced[0] = 42;
        enhanced[1] = 43;
        
        // Make read-only
        enhanced.make_read_only();
        assert!(enhanced.is_read_only());
        
        // We can still read
        assert_eq!(enhanced[0], 42);
        
        // Make writable again
        enhanced.make_writable();
        assert!(!enhanced.is_read_only());
        
        // Now we can modify
        enhanced[2] = 44;
        assert_eq!(enhanced[2], 44);
    }
}