/*!
WebAssembly-specific memory operations.

This module provides WebAssembly implementations of memory operations
as well as wrappers for Web Crypto API.
*/

use crate::core::memory::platform::PlatformMemory;
use crate::core::memory::error::{Error, Result};

/// WebAssembly-specific memory operations implementation
pub struct WasmMemory {
    has_secure_random: bool,
}

impl WasmMemory {
    pub fn new() -> Self {
        // Check if we're in a secure context (for Web Crypto API)
        let has_secure_random = Self::check_secure_context();
        
        Self { has_secure_random }
    }
    
    /// Check if we're running in a secure context
    fn check_secure_context() -> bool {
        #[cfg(feature = "wasm-compat")]
        {
            use wasm_bindgen::prelude::*;
            
            // Try to detect if we're in a secure context
            if let Ok(window) = js_sys::global().dyn_into::<web_sys::Window>() {
                if let Some(is_secure) = js_sys::Reflect::get(&window, &JsValue::from_str("isSecureContext"))
                    .ok()
                    .and_then(|v| v.as_bool()) {
                    return is_secure;
                }
            }
            false
        }
        
        #[cfg(not(feature = "wasm-compat"))]
        {
            false
        }
    }
    
    /// Check if secure random is available
    pub fn has_secure_random(&self) -> bool {
        self.has_secure_random
    }
    
    /// Fill a buffer with secure random data
    #[cfg(feature = "wasm-compat")]
    pub fn fill_random(&self, buffer: &mut [u8]) -> Result<()> {
        use wasm_bindgen::prelude::*;
        use js_sys::Uint8Array;
        
        if !self.has_secure_random {
            return Err(Error::Other("Secure random not available".to_string()));
        }
        
        let array = Uint8Array::new_with_length(buffer.len() as u32);
        
        // Use Web Crypto API to fill with random data
        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_namespace = crypto)]
            fn getRandomValues(array: &Uint8Array);
        }
        
        // Fill the array with random values
        getRandomValues(&array);
        
        // Copy back to the buffer
        array.copy_to(buffer);
        
        Ok(())
    }
    
    #[cfg(not(feature = "wasm-compat"))]
    pub fn fill_random(&self, _buffer: &mut [u8]) -> Result<()> {
        Err(Error::Other("WASM compat feature not enabled".to_string()))
    }
}

impl PlatformMemory for WasmMemory {
    fn lock_memory(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        // Memory locking not available in WebAssembly
        Ok(())
    }
    
    fn unlock_memory(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        // Memory locking not available in WebAssembly
        Ok(())
    }
    
    fn protect_memory_readonly(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        // Memory protection not available in WebAssembly
        Ok(())
    }
    
    fn protect_memory_readwrite(&self, _ptr: *const u8, _size: usize) -> Result<()> {
        // Memory protection not available in WebAssembly
        Ok(())
    }
    
    fn page_size(&self) -> usize {
        // Standard WebAssembly page size
        65536
    }
}

/// WebAssembly-specific memory manager
pub struct WasmMemoryManager {
    /// Underlying memory manager
    manager: crate::core::memory::manager::memory_manager::SecureMemoryManager,
    /// WebAssembly memory operations
    wasm_memory: WasmMemory,
}

impl WasmMemoryManager {
    /// Create a new WebAssembly memory manager
    pub fn new() -> Self {
        let wasm_memory = WasmMemory::new();
        let manager = crate::core::memory::manager::memory_manager::SecureMemoryManager::new(
            crate::core::memory::traits::security::MemorySecurity::Standard
        );
        
        Self { manager, wasm_memory }
    }
    
    /// Check if secure random is available
    pub fn has_secure_random(&self) -> bool {
        self.wasm_memory.has_secure_random()
    }
    
    /// Fill a buffer with secure random data
    pub fn fill_random(&self, buffer: &mut [u8]) -> Result<()> {
        self.wasm_memory.fill_random(buffer)
    }
    
    /// Get the underlying memory manager
    pub fn inner(&self) -> &crate::core::memory::manager::memory_manager::SecureMemoryManager {
        &self.manager
    }
    
    /// Get mutable access to the underlying memory manager
    pub fn inner_mut(&mut self) -> &mut crate::core::memory::manager::memory_manager::SecureMemoryManager {
        &mut self.manager
    }
}

impl Default for WasmMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wasm_memory() {
        let memory = WasmMemory::new();
        
        // Check page size
        assert_eq!(memory.page_size(), 65536);
        
        // These operations should succeed even though they don't do anything
        assert!(memory.lock_memory(std::ptr::null(), 0).is_ok());
        assert!(memory.unlock_memory(std::ptr::null(), 0).is_ok());
        assert!(memory.protect_memory_readonly(std::ptr::null(), 0).is_ok());
        assert!(memory.protect_memory_readwrite(std::ptr::null(), 0).is_ok());
    }
}