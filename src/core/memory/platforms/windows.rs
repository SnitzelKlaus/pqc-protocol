/*!
Windows-specific memory operations.

This module provides Windows implementations of memory protection operations
like VirtualLock and VirtualProtect.
*/

use crate::core::memory::platform::PlatformMemory;
use crate::core::memory::error::{Error, Result};

/// Windows-specific memory operations implementation
pub struct WindowsMemory {
    page_size: usize,
}

impl WindowsMemory {
    pub fn new() -> Self {
        // Get the system page size
        let page_size = unsafe { 
            let mut system_info = std::mem::zeroed();
            winapi::um::sysinfoapi::GetSystemInfo(&mut system_info);
            system_info.dwPageSize as usize
        };
        
        Self { page_size }
    }
}

impl PlatformMemory for WindowsMemory {
    fn lock_memory(&self, ptr: *const u8, size: usize) -> Result<()> {
        if size == 0 || ptr.is_null() {
            return Ok(());
        }
        
        // Align pointer and size to page boundaries
        let aligned_ptr = self.align_to_page(ptr);
        let aligned_size = self.aligned_size(ptr, size);
        
        // Try to lock the memory
        let result = unsafe { 
            winapi::um::memoryapi::VirtualLock(aligned_ptr as *mut _, aligned_size) 
        };
        
        if result != 0 {
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(Error::LockFailed(format!("VirtualLock failed with error: {}", error)))
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
        let result = unsafe { 
            winapi::um::memoryapi::VirtualUnlock(aligned_ptr as *mut _, aligned_size) 
        };
        
        if result != 0 {
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(Error::Other(format!("VirtualUnlock failed with error: {}", error)))
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
        let mut old_protect = 0;
        let result = unsafe { 
            winapi::um::memoryapi::VirtualProtect(
                aligned_ptr as *mut _, 
                aligned_size, 
                winapi::um::winnt::PAGE_READONLY, 
                &mut old_protect
            ) 
        };
        
        if result != 0 {
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(Error::ProtectionFailed(format!("VirtualProtect(PAGE_READONLY) failed with error: {}", error)))
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
        let mut old_protect = 0;
        let result = unsafe { 
            winapi::um::memoryapi::VirtualProtect(
                aligned_ptr as *mut _, 
                aligned_size, 
                winapi::um::winnt::PAGE_READWRITE, 
                &mut old_protect
            ) 
        };
        
        if result != 0 {
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(Error::ProtectionFailed(format!("VirtualProtect(PAGE_READWRITE) failed with error: {}", error)))
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
    fn test_windows_memory() {
        let memory = WindowsMemory::new();
        
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