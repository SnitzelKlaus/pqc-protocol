/*!
Platform-specific memory configuration.

This module provides configurations for different platforms, including
resource-constrained environments like embedded systems and WebAssembly.
*/

use crate::core::memory::traits::security::MemorySecurity;
use crate::core::memory::manager::memory_manager::SecureMemoryManager;

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
    
    /// Memory protection features
    features: MemoryFeatures,
}

/// Specific memory protection features that can be enabled/disabled
#[derive(Debug, Clone, Copy)]
pub struct MemoryFeatures {
    /// Whether to use memory locking
    pub use_memory_locking: bool,
    
    /// Whether to use canary values
    pub use_canary: bool,
    
    /// Whether to zero memory on free
    pub zero_on_free: bool,
    
    /// Whether to use secure RNG for padding
    pub use_secure_rng: bool,
    
    /// Amount of padding to use (in bytes)
    pub padding_size: usize,
}

impl Default for MemoryFeatures {
    fn default() -> Self {
        Self {
            use_memory_locking: true,
            use_canary: true,
            zero_on_free: true,
            use_secure_rng: true,
            padding_size: 64,
        }
    }
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
            features: MemoryFeatures::default(),
        }
    }
    
    /// Create configuration for embedded platform
    pub fn embedded() -> Self {
        let mut features = MemoryFeatures::default();
        features.use_memory_locking = false;
        features.use_canary = cfg!(feature = "embedded-canary");
        features.use_secure_rng = cfg!(feature = "embedded-rng");
        features.padding_size = 16;
        
        Self {
            platform: Platform::Embedded,
            security_level: MemorySecurity::Standard,
            features,
        }
    }
    
    /// Create configuration for WebAssembly
    pub fn wasm() -> Self {
        let mut features = MemoryFeatures::default();
        features.use_memory_locking = false;
        features.padding_size = 32;
        
        Self {
            platform: Platform::Wasm,
            security_level: MemorySecurity::Standard,
            features,
        }
    }
    
    /// Create configuration for mobile platform
    pub fn mobile() -> Self {
        let mut features = MemoryFeatures::default();
        features.padding_size = 32;
        
        Self {
            platform: Platform::Mobile,
            security_level: MemorySecurity::Standard,
            features,
        }
    }
    
    /// Get the platform type
    pub fn platform(&self) -> Platform {
        self.platform
    }
    
    /// Get the security level
    pub fn security_level(&self) -> MemorySecurity {
        self.security_level
    }
    
    /// Get the features configuration
    pub fn features(&self) -> &MemoryFeatures {
        &self.features
    }
    
    /// Get mutable access to features configuration
    pub fn features_mut(&mut self) -> &mut MemoryFeatures {
        &mut self.features
    }
    
    /// Set memory security level
    pub fn with_security_level(mut self, level: MemorySecurity) -> Self {
        self.security_level = level;
        self
    }
    
    /// Enable or disable memory locking
    pub fn with_memory_locking(mut self, enable: bool) -> Self {
        self.features.use_memory_locking = enable;
        self
    }
    
    /// Enable or disable canary protection
    pub fn with_canary(mut self, enable: bool) -> Self {
        self.features.use_canary = enable;
        self
    }
    
    /// Enable or disable zeroing memory on free
    pub fn with_zero_on_free(mut self, enable: bool) -> Self {
        self.features.zero_on_free = enable;
        self
    }
    
    /// Enable or disable secure RNG for padding
    pub fn with_secure_rng(mut self, enable: bool) -> Self {
        self.features.use_secure_rng = enable;
        self
    }
    
    /// Set padding size
    pub fn with_padding_size(mut self, size: usize) -> Self {
        self.features.padding_size = size;
        self
    }
    
    /// Apply configuration to a memory manager
    pub fn apply_to_manager(&self, manager: &mut SecureMemoryManager) {
        // Set security level
        manager.set_security_level(self.security_level);
        
        // Configure individual settings
        if self.features.use_memory_locking {
            manager.enable_memory_locking();
        } else {
            manager.disable_memory_locking();
        }
        
        if self.features.use_canary {
            manager.enable_canary_protection();
        } else {
            manager.disable_canary_protection();
        }
        
        if self.features.zero_on_free {
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
        target_arch = "riscv32",
        target_arch = "riscv64",
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