/*!
WebAssembly specific memory management for the PQC protocol.

This module provides memory management utilities specifically for
WebAssembly targets with their unique constraints.
*/

#[cfg(target_arch = "wasm32")]
use super::secure_memory_manager::SecureMemoryManager;
#[cfg(target_arch = "wasm32")]
use super::memory_security::MemorySecurity;

/// WASM-specific version of the memory manager
#[cfg(target_arch = "wasm32")]
pub struct WasmMemoryManager {
    /// Base memory manager
    inner: SecureMemoryManager,
    /// Whether secure random is available
    has_secure_random: bool,
}

#[cfg(target_arch = "wasm32")]
impl WasmMemoryManager {
    /// Create a new WASM-specific memory manager
    pub fn new() -> Self {
        // Check if secure random is available
        let has_secure_random = js_sys::crypto::is_secure_context();
        
        Self {
            inner: SecureMemoryManager::new(MemorySecurity::Standard),
            has_secure_random,
        }
    }
    
    /// Check if secure random is available
    pub fn has_secure_random(&self) -> bool {
        self.has_secure_random
    }
    
    /// Get a reference to the inner manager
    pub fn inner(&self) -> &SecureMemoryManager {
        &self.inner
    }
    
    /// Get a mutable reference to the inner manager
    pub fn inner_mut(&mut self) -> &mut SecureMemoryManager {
        &mut self.inner
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use super::*;
    
    #[test]
    fn test_wasm_manager_creation() {
        let manager = WasmMemoryManager::new();
        assert_eq!(manager.inner().security_level(), MemorySecurity::Standard);
    }
}