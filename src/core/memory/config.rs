/*!
Platform-specific memory configuration.

This module provides configurations for different platforms, including
resource-constrained environments like embedded systems and WebAssembly.
*/

use crate::core::memory::{SecureMemoryManager, MemorySecurity};

/// Platform types for memory configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Standard desktop/server environment
    Standard,
    
    /// Embedded system with limited resources
    Embedded,
    
    /// WebAssembly environment in browser
    Wasm,
    
    /// Mobile device
    Mobile,
}

/// Memory configuration for different platforms
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Target platform
    platform: Platform,
    
    /// Memory security level
    security_level: MemorySecurity,
    
    /// Whether to use memory locking
    use_memory_locking: bool,
    
    /// Whether to use canary values
    use_canary: bool,
    
    /// Whether to zero memory on free
    zero_on_free: bool,
    
    /// Whether to use secure RNG for padding
    use_secure_rng: bool,
    
    /// Amount of padding to use (in bytes)
    padding_size: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self::standard()
    }
}

impl MemoryConfig {
    /// Create configuration for standard platform
    pub fn standard() -> Self {
        Self {
            platform: Platform::Standard,
            security_level: MemorySecurity::Standard,
            use_memory_locking: true,
            use_canary: true,
            zero_on_free: true,
            use_secure_rng: true,
            padding_size: 64, // Default padding size
        }
    }
    
    /// Create configuration for embedded platform
    pub fn embedded() -> Self {
        Self {
            platform: Platform::Embedded,
            security_level: MemorySecurity::Standard,
            use_memory_locking: false, // Often not available on embedded
            use_canary: false, // Reduce overhead
            zero_on_free: true, // Still zero sensitive data
            use_secure_rng: false, // May not have good RNG
            padding_size: 16, // Minimal padding
        }
    }
    
    /// Create configuration for WebAssembly
    pub fn wasm() -> Self {
        Self {
            platform: Platform::Wasm,
            security_level: MemorySecurity::Standard,
            use_memory_locking: false, // Not available in WASM
            use_canary: true, // Still use overflow protection
            zero_on_free: true, // Still zero sensitive data
            use_secure_rng: true, // Use browser's crypto.getRandomValues
            padding_size: 32, // Moderate padding
        }
    }
    
    /// Create configuration for mobile platform
    pub fn mobile() -> Self {
        Self {
            platform: Platform::Mobile,
            security_level: MemorySecurity::Standard,
            use_memory_locking: true, // Available on most mobile platforms
            use_canary: true,
            zero_on_free: true,
            use_secure_rng: true,
            padding_size: 32, // Moderate padding
        }
    }
    
    /// Set memory security level
    pub fn with_security_level(mut self, level: MemorySecurity) -> Self {
        self.security_level = level;
        self
    }
    
    /// Enable or disable memory locking
    pub fn with_memory_locking(mut self, enable: bool) -> Self {
        self.use_memory_locking = enable;
        self
    }
    
    /// Enable or disable canary protection
    pub fn with_canary(mut self, enable: bool) -> Self {
        self.use_canary = enable;
        self
    }
    
    /// Enable or disable zeroing memory on free
    pub fn with_zero_on_free(mut self, enable: bool) -> Self {
        self.zero_on_free = enable;
        self
    }
    
    /// Enable or disable secure RNG for padding
    pub fn with_secure_rng(mut self, enable: bool) -> Self {
        self.use_secure_rng = enable;
        self
    }
    
    /// Set padding size
    pub fn with_padding_size(mut self, size: usize) -> Self {
        self.padding_size = size;
        self
    }
    
    /// Apply configuration to a memory manager
    pub fn apply_to_manager(&self, manager: &mut SecureMemoryManager) {
        // Set security level
        manager.set_security_level(self.security_level);
        
        // Configure individual settings
        if self.use_memory_locking {
            manager.enable_memory_locking();
        } else {
            manager.disable_memory_locking();
        }
        
        if self.use_canary {
            manager.enable_canary_protection();
        } else {
            manager.disable_canary_protection();
        }
        
        if self.zero_on_free {
            manager.enable_zero_on_free();
        } else {
            manager.disable_zero_on_free();
        }
    }
    
    /// Create a memory manager with this configuration
    pub fn create_manager(&self) -> SecureMemoryManager {
        let mut manager = SecureMemoryManager::new(self.security_level);
        
        // Apply settings
        self.apply_to_manager(&mut manager);
        
        manager
    }
}

/// Auto-detect best memory configuration for current platform
pub fn auto_detect_platform() -> Platform {
    #[cfg(target_arch = "wasm32")]
    {
        return Platform::Wasm;
    }
    
    #[cfg(any(
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "riscv",
        all(target_arch = "aarch64", target_pointer_width = "32")
    ))]
    {
        return Platform::Embedded;
    }
    
    #[cfg(any(
        target_os = "android",
        target_os = "ios"
    ))]
    {
        return Platform::Mobile;
    }
    
    // Default to standard
    Platform::Standard
}

/// Create platform-appropriate memory configuration
pub fn for_current_platform() -> MemoryConfig {
    match auto_detect_platform() {
        Platform::Wasm => MemoryConfig::wasm(),
        Platform::Embedded => MemoryConfig::embedded(),
        Platform::Mobile => MemoryConfig::mobile(),
        Platform::Standard => MemoryConfig::standard(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_platform_configs() {
        // Test standard config
        let standard = MemoryConfig::standard();
        assert_eq!(standard.platform, Platform::Standard);
        assert!(standard.use_memory_locking);
        assert!(standard.use_canary);
        
        // Test embedded config
        let embedded = MemoryConfig::embedded();
        assert_eq!(embedded.platform, Platform::Embedded);
        assert!(!embedded.use_memory_locking);
        assert!(!embedded.use_canary);
        
        // Test WASM config
        let wasm = MemoryConfig::wasm();
        assert_eq!(wasm.platform, Platform::Wasm);
        assert!(!wasm.use_memory_locking);
        assert!(wasm.use_canary);
    }
    
    #[test]
    fn test_custom_config() {
        let custom = MemoryConfig::standard()
            .with_security_level(MemorySecurity::Maximum)
            .with_padding_size(128)
            .with_memory_locking(false);
        
        assert_eq!(custom.security_level, MemorySecurity::Maximum);
        assert_eq!(custom.padding_size, 128);
        assert!(!custom.use_memory_locking);
    }
    
    #[test]
    fn test_apply_to_manager() {
        let config = MemoryConfig::embedded();
        let mut manager = SecureMemoryManager::default();
        
        // Before applying config
        assert_eq!(manager.security_level(), MemorySecurity::Standard);
        assert!(manager.is_memory_locking_enabled());
        
        // Apply embedded config
        config.apply_to_manager(&mut manager);
        
        // After applying config
        assert!(!manager.is_memory_locking_enabled());
    }
}