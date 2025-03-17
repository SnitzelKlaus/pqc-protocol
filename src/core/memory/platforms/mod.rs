/*!
Platform abstraction layer for memory operations.

This module provides a unified interface for platform-specific memory operations,
such as locking memory to prevent swapping and setting memory protection levels.
*/

use crate::core::memory::error::Result;

// Platform-specific implementations
#[cfg(unix)]
pub mod unix;

#[cfg(all(windows, feature = "windows-compat"))]
pub mod windows;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// Interface for platform-specific memory operations
pub trait PlatformMemory: Send + Sync {
    /// Lock memory to prevent it from being swapped to disk
    fn lock_memory(&self, ptr: *const u8, size: usize) -> Result<()>;
    
    /// Unlock previously locked memory
    fn unlock_memory(&self, ptr: *const u8, size: usize) -> Result<()>;
    
    /// Make memory read-only
    fn protect_memory_readonly(&self, ptr: *const u8, size: usize) -> Result<()>;
    
    /// Make memory readable and writable
    fn protect_memory_readwrite(&self, ptr: *const u8, size: usize) -> Result<()>;
    
    /// Get the system page size
    fn page_size(&self) -> usize;
    
    /// Align a pointer to page boundaries
    fn align_to_page(&self, ptr: *const u8) -> *const u8 {
        let page_size = self.page_size();
        let addr = ptr as usize;
        let aligned = (addr & !(page_size - 1)) as *const u8;
        aligned
    }
    
    /// Get size covering the memory region, aligned to page boundaries
    fn aligned_size(&self, ptr: *const u8, size: usize) -> usize {
        let page_size = self.page_size();
        let addr = ptr as usize;
        let aligned_addr = addr & !(page_size - 1);
        let offset = addr - aligned_addr;
        let aligned_size = (offset + size + page_size - 1) & !(page_size - 1);
        aligned_size
    }
}

/// Get the appropriate platform implementation for the current target
pub fn get_platform_impl() -> std::sync::Arc<dyn PlatformMemory> {
    use std::sync::Arc;
    
    // Attempt to detect the platform and provide the appropriate implementation
    #[cfg(unix)]
    {
        return Arc::new(unix::UnixMemory::new());
    }
    
    #[cfg(all(windows, feature = "windows-compat"))]
    {
        return Arc::new(windows::WindowsMemory::new());
    }
    
    #[cfg(target_arch = "wasm32")]
    {
        return Arc::new(wasm::WasmMemory::new());
    }
    
    // Fallback implementation
    Arc::new(NoopMemory::new())
}

/// Fallback implementation that does nothing
pub struct NoopMemory {
    page_size: usize,
}

impl NoopMemory {
    pub fn new() -> Self {
        Self {
            page_size: 4096, // Standard page size for most platforms
        }
    }
}

impl PlatformMemory for NoopMemory {
    fn lock_memory(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        Ok(()) // No-op implementation
    }
    
    fn unlock_memory(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        Ok(()) // No-op implementation
    }
    
    fn protect_memory_readonly(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        Ok(()) // No-op implementation
    }
    
    fn protect_memory_readwrite(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        Ok(()) // No-op implementation
    }
    
    fn page_size(&self) -> usize {
        self.page_size // Standard page size for most platforms
    }
}