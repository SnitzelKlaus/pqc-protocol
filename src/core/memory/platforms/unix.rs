/*!
Unix-specific memory operations.

This module provides Unix implementations of memory protection operations
like mlock and mprotect.
*/

use crate::core::memory::platform::PlatformMemory;
use crate::core::memory::error::{Error, Result};

/// Unix-specific memory operations implementation
pub struct UnixMemory {
    page_size: usize,
}

impl UnixMemory {
    pub fn new() -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        Self { page_size }
    }
}

impl PlatformMemory for UnixMemory {
    fn lock_memory(&self, ptr: *const u8, size: usize) -> Result<()> {
        if size == 0 || ptr.is_null() {
            return Ok(());
        }
        
        // Align pointer and size to page boundaries
        let aligned_ptr = self.align_to_page(ptr);
        let aligned_size = self.aligned_size(ptr, size);
        
        // Try to lock the memory
        let result = unsafe { libc::mlock(aligned_ptr as *const _, aligned_size) };
        
        if result == 0 {
            Ok(())
        } else {
            // Get the error code
            let err = unsafe { *libc::__errno_location() };
            if err == libc::ENOMEM {
                // If we don't have permission, try mlockall as a fallback
                let mlockall_result = unsafe { 
                    libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) 
                };
                
                if mlockall_result == 0 {
                    Ok(())
                } else {
                    Err(Error::LockFailed(format!("mlock failed with error: {}", err)))
                }
            } else {
                Err(Error::LockFailed(format!("mlock failed with error: {}", err)))
            }
        }
    }
    
    fn unlock_memory(&self, ptr: *const u8, size: usize) -> Result<()> {
        if size == 0 || ptr.is_null() {
            return Ok(());
        }
        
        // Align pointer and size to page boundaries
        let aligned_ptr = self.align_to_page(ptr);
        let aligned_size = self.aligned_size(ptr, size);
        
        // Unlock the memory
        let result = unsafe { libc::munlock(aligned_ptr as *const _, aligned_size) };
        
        if result == 0 {
            Ok(())
        } else {
            let err = unsafe { *libc::__errno_location() };
            Err(Error::Other(format!("munlock failed with error: {}", err)))
        }
    }
    
    fn protect_memory_readonly(&self, ptr: *const u8, size: usize) -> Result<()> {
        if size == 0 || ptr.is_null() {
            return Ok(());
        }
        
        // Align pointer and size to page boundaries
        let aligned_ptr = self.align_to_page(ptr);
        let aligned_size = self.aligned_size(ptr, size);
        
        // Make the memory read-only
        let result = unsafe { 
            libc::mprotect(aligned_ptr as *mut _, aligned_size, libc::PROT_READ) 
        };
        
        if result == 0 {
            Ok(())
        } else {
            let err = unsafe { *libc::__errno_location() };
            Err(Error::ProtectionFailed(format!("mprotect(PROT_READ) failed with error: {}", err)))
        }
    }
    
    fn protect_memory_readwrite(&self, ptr: *const u8, size: usize) -> Result<()> {
        if size == 0 || ptr.is_null() {
            return Ok(());
        }
        
        // Align pointer and size to page boundaries
        let aligned_ptr = self.align_to_page(ptr);
        let aligned_size = self.aligned_size(ptr, size);
        
        // Make the memory readable and writable
        let result = unsafe { 
            libc::mprotect(
                aligned_ptr as *mut _, 
                aligned_size, 
                libc::PROT_READ | libc::PROT_WRITE
            ) 
        };
        
        if result == 0 {
            Ok(())
        } else {
            let err = unsafe { *libc::__errno_location() };
            Err(Error::ProtectionFailed(format!("mprotect(PROT_READ|PROT_WRITE) failed with error: {}", err)))
        }
    }
    
    fn page_size(&self) -> usize {
        self.page_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unix_memory() {
        let memory = UnixMemory::new();
        
        // Check page size
        assert!(memory.page_size() > 0);
        
        // Allocate some memory for testing
        let mut buffer = vec![0u8; 4096];
        
        // Try to lock it
        let lock_result = memory.lock_memory(buffer.as_ptr(), buffer.len());
        println!("Lock result: {:?}", lock_result);
        
        // Try to protect it
        let protect_result = memory.protect_memory_readonly(buffer.as_ptr(), buffer.len());
        println!("Protect result: {:?}", protect_result);
        
        // Restore original protection
        let unprotect_result = memory.protect_memory_readwrite(buffer.as_ptr(), buffer.len());
        println!("Unprotect result: {:?}", unprotect_result);
        
        // Unlock memory
        let unlock_result = memory.unlock_memory(buffer.as_ptr(), buffer.len());
        println!("Unlock result: {:?}", unlock_result);
    }
}