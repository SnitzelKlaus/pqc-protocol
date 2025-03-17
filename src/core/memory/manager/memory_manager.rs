/*!
Enhanced secure memory manager for the PQC protocol.

This module provides a centralized manager for secure memory operations:
- Controls memory security features (locking, canary values, etc.)
- Factory methods for creating secure memory containers
- Integration with hardware security modules
- Platform-specific memory operations
*/

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::core::memory::traits::security::{MemorySecurity, SecureMemoryFactory};
use crate::core::memory::containers::base_container::SecureContainer;
use crate::core::memory::containers::heap_container::SecureHeap;
use crate::core::memory::containers::readonly_container::ReadOnlyContainer;
use crate::core::memory::containers::stack_container::SecureStack;
use crate::core::memory::platforms::{PlatformMemory, get_platform_impl};
use crate::core::memory::error::{Error, Result};

#[cfg(feature = "hardware-security")]
use crate::core::memory::hardware::HardwareSecurityCapability;

/// Enhanced secure memory manager with additional protections
pub struct SecureMemoryManager {
    /// Current memory security level
    level: MemorySecurity,
    
    /// Whether automatic key erasure is enabled
    auto_erase: bool,
    
    /// Whether memory locking is enabled
    memory_locking: AtomicBool,
    
    /// Whether canary values are used for buffer overflow detection
    canary_protection: AtomicBool,
    
    /// Whether sensitive memory is zeroed when freed
    zero_on_free: AtomicBool,
    
    /// Whether to use hardware security modules when available
    use_hardware_security: AtomicBool,
    
    /// Whether to use constant-time operations
    use_constant_time: AtomicBool,
    
    /// Whether to use read-only memory protection
    use_read_only_protection: AtomicBool,
    
    /// Platform-specific memory operations
    platform: Arc<dyn PlatformMemory>,
    
    /// Hardware security manager for TPM, SGX, etc.
    #[cfg(feature = "hardware-security")]
    hw_security: Option<crate::core::memory::hardware::HardwareSecurityManager>,
}

impl SecureMemoryManager {
    /// Create a new secure memory manager with the specified security level
    pub fn new(level: MemorySecurity) -> Self {
        // Get platform-specific implementation
        let platform = get_platform_impl();
        
        // Initialize hardware security if available
        #[cfg(feature = "hardware-security")]
        let (hw_security, has_hw_security) = {
            let hw = crate::core::memory::hardware::HardwareSecurityManager::new();
            (Some(hw), hw.is_available())
        };
        
        #[cfg(not(feature = "hardware-security"))]
        let has_hw_security = false;
        
        let manager = Self {
            level,
            auto_erase: true,
            
            memory_locking: AtomicBool::new(cfg!(feature = "memory-lock")),
            canary_protection: AtomicBool::new(cfg!(feature = "memory-canary")),
            zero_on_free: AtomicBool::new(true), // Always enabled by default
            
            use_hardware_security: AtomicBool::new(has_hw_security),
            use_constant_time: AtomicBool::new(true),
            use_read_only_protection: AtomicBool::new(cfg!(feature = "memory-enhanced")),
            
            platform,
            
            #[cfg(feature = "hardware-security")]
            hw_security,
        };
        
        manager
    }
    
    /// Create a new secure memory manager with default security level
    pub fn default() -> Self {
        Self::new(MemorySecurity::Standard)
    }
    
    /// Create a new secure memory manager with enhanced security
    pub fn enhanced() -> Self {
        Self::new(MemorySecurity::Enhanced)
    }
    
    /// Create a new secure memory manager with maximum security
    pub fn maximum() -> Self {
        Self::new(MemorySecurity::Maximum)
    }
    
    /// Get the current security level
    pub fn security_level(&self) -> MemorySecurity {
        self.level
    }
    
    /// Set the security level
    pub fn set_security_level(&mut self, level: MemorySecurity) {
        self.level = level;
        
        // Adjust settings based on the new security level
        match level {
            MemorySecurity::Standard => {
                // Standard settings - basic protections
                self.enable_zero_on_free();
                
                if cfg!(feature = "memory-lock") {
                    self.enable_memory_locking();
                }
            },
            MemorySecurity::Enhanced => {
                // Enhanced settings - all standard protections plus canaries
                self.enable_zero_on_free();
                
                if cfg!(feature = "memory-lock") {
                    self.enable_memory_locking();
                }
                
                if cfg!(feature = "memory-canary") {
                    self.enable_canary_protection();
                }
            },
            MemorySecurity::Maximum => {
                // Maximum settings - all protections enabled
                self.enable_zero_on_free();
                
                if cfg!(feature = "memory-lock") {
                    self.enable_memory_locking();
                }
                
                if cfg!(feature = "memory-canary") {
                    self.enable_canary_protection();
                }
                
                if cfg!(feature = "memory-enhanced") {
                    self.enable_read_only_protection();
                }
                
                self.enable_constant_time();
                
                #[cfg(feature = "hardware-security")]
                self.enable_hardware_security();
            },
        }
    }
    
    //--------------------------------------------------------------
    // Security feature getters/setters
    //--------------------------------------------------------------
    
    /// Check if memory locking is enabled
    pub fn is_memory_locking_enabled(&self) -> bool {
        self.memory_locking.load(Ordering::Relaxed)
    }
    
    /// Enable memory locking
    pub fn enable_memory_locking(&self) {
        self.memory_locking.store(true, Ordering::Relaxed);
    }
    
    /// Disable memory locking
    pub fn disable_memory_locking(&self) {
        self.memory_locking.store(false, Ordering::Relaxed);
    }
    
    /// Check if canary protection is enabled
    pub fn is_canary_protection_enabled(&self) -> bool {
        self.canary_protection.load(Ordering::Relaxed)
    }
    
    /// Enable canary protection
    pub fn enable_canary_protection(&self) {
        self.canary_protection.store(true, Ordering::Relaxed);
    }
    
    /// Disable canary protection
    pub fn disable_canary_protection(&self) {
        self.canary_protection.store(false, Ordering::Relaxed);
    }
    
    /// Check if zero-on-free is enabled
    pub fn is_zero_on_free_enabled(&self) -> bool {
        self.zero_on_free.load(Ordering::Relaxed)
    }
    
    /// Enable zero-on-free
    pub fn enable_zero_on_free(&self) {
        self.zero_on_free.store(true, Ordering::Relaxed);
    }
    
    /// Disable zero-on-free
    pub fn disable_zero_on_free(&self) {
        self.zero_on_free.store(false, Ordering::Relaxed);
    }
    
    /// Check if hardware security is enabled
    pub fn is_hardware_security_enabled(&self) -> bool {
        self.use_hardware_security.load(Ordering::Relaxed)
    }
    
    /// Enable hardware security
    pub fn enable_hardware_security(&self) {
        self.use_hardware_security.store(true, Ordering::Relaxed);
    }
    
    /// Disable hardware security
    pub fn disable_hardware_security(&self) {
        self.use_hardware_security.store(false, Ordering::Relaxed);
    }
    
    /// Check if constant-time operations are enabled
    pub fn is_constant_time_enabled(&self) -> bool {
        self.use_constant_time.load(Ordering::Relaxed)
    }
    
    /// Enable constant-time operations
    pub fn enable_constant_time(&self) {
        self.use_constant_time.store(true, Ordering::Relaxed);
    }
    
    /// Disable constant-time operations
    pub fn disable_constant_time(&self) {
        self.use_constant_time.store(false, Ordering::Relaxed);
    }
    
    /// Check if read-only memory protection is enabled
    pub fn is_read_only_protection_enabled(&self) -> bool {
        self.use_read_only_protection.load(Ordering::Relaxed)
    }
    
    /// Enable read-only memory protection
    pub fn enable_read_only_protection(&self) {
        self.use_read_only_protection.store(true, Ordering::Relaxed);
    }
    
    /// Disable read-only memory protection
    pub fn disable_read_only_protection(&self) {
        self.use_read_only_protection.store(false, Ordering::Relaxed);
    }
    
    /// Check if auto-erase is enabled
    pub fn is_auto_erase_enabled(&self) -> bool {
        self.auto_erase
    }
    
    /// Enable auto-erase
    pub fn enable_auto_erase(&mut self) {
        self.auto_erase = true;
    }
    
    /// Disable auto-erase
    pub fn disable_auto_erase(&mut self) {
        self.auto_erase = false;
    }
    
    /// Get the platform-specific memory implementation
    pub fn platform(&self) -> &dyn PlatformMemory {
        &*self.platform
    }
    
    //--------------------------------------------------------------
    // Hardware security methods
    //--------------------------------------------------------------
    
    /// Get the hardware security manager, if available
    #[cfg(feature = "hardware-security")]
    pub fn hardware_security_manager(&self) -> Option<&crate::core::memory::hardware::HardwareSecurityManager> {
        self.hw_security.as_ref()
    }
    
    /// Store a key in hardware security module
    #[cfg(feature = "hardware-security")]
    pub fn store_key_in_hsm(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        if !self.is_hardware_security_enabled() {
            return Ok(());
        }
        
        if let Some(hw) = &self.hw_security {
            hw.store_key(key_id, key_data)
                .map_err(|e| Error::HsmError(format!("Failed to store key: {}", e)))
        } else {
            Ok(())
        }
    }
    
    /// Retrieve a key from hardware security module
    #[cfg(feature = "hardware-security")]
    pub fn retrieve_key_from_hsm(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        if !self.is_hardware_security_enabled() {
            return Ok(None);
        }
        
        if let Some(hw) = &self.hw_security {
            hw.retrieve_key(key_id)
                .map_err(|e| Error::HsmError(format!("Failed to retrieve key: {}", e)))
        } else {
            Ok(None)
        }
    }
    
    /// Sign data using a key in the hardware security module
    #[cfg(feature = "hardware-security")]
    pub fn sign_with_hsm(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        if !self.is_hardware_security_enabled() {
            return Err(Error::HsmError("Hardware security not enabled".to_string()));
        }
        
        if let Some(hw) = &self.hw_security {
            hw.sign_data(key_id, data)
                .map_err(|e| Error::HsmError(format!("Failed to sign data: {}", e)))
        } else {
            Err(Error::HsmError("Hardware security module not available".to_string()))
        }
    }
    
    /// Generate random data using hardware security module
    #[cfg(feature = "hardware-security")]
    pub fn generate_random_with_hsm(&self, length: usize) -> Result<Vec<u8>> {
        if !self.is_hardware_security_enabled() {
            // Fall back to using the system RNG
            use rand::{thread_rng, RngCore};
            let mut rng = thread_rng();
            let mut buffer = vec![0u8; length];
            rng.fill_bytes(&mut buffer);
            return Ok(buffer);
        }
        
        if let Some(hw) = &self.hw_security {
            hw.generate_random(length)
                .map_err(|e| Error::HsmError(format!("Failed to generate random data: {}", e)))
        } else {
            // Fall back to using the system RNG
            use rand::{thread_rng, RngCore};
            let mut rng = thread_rng();
            let mut buffer = vec![0u8; length];
            rng.fill_bytes(&mut buffer);
            Ok(buffer)
        }
    }
    
    /// Check if a specific hardware security capability is available
    #[cfg(feature = "hardware-security")]
    pub fn has_hw_capability(&self, capability: HardwareSecurityCapability) -> bool {
        if !self.is_hardware_security_enabled() {
            return false;
        }
        
        if let Some(hw) = &self.hw_security {
            hw.supports(capability)
        } else {
            false
        }
    }
    
    //--------------------------------------------------------------
    // Placeholders for hardware security when the feature is disabled
    //--------------------------------------------------------------
    
    /// Placeholder for hardware security manager
    #[cfg(not(feature = "hardware-security"))]
    pub fn hardware_security_manager(&self) -> Option<()> {
        None
    }
    
    /// Placeholder for store key in HSM
    #[cfg(not(feature = "hardware-security"))]
    pub fn store_key_in_hsm(&self, _key_id: &str, _key_data: &[u8]) -> Result<()> {
        Ok(())
    }
    
    /// Placeholder for retrieve key from HSM
    #[cfg(not(feature = "hardware-security"))]
    pub fn retrieve_key_from_hsm(&self, _key_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    
    /// Placeholder for sign with HSM
    #[cfg(not(feature = "hardware-security"))]
    pub fn sign_with_hsm(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Other("Hardware security not supported".to_string()))
    }
    
    /// Placeholder for generate random with HSM
    #[cfg(not(feature = "hardware-security"))]
    pub fn generate_random_with_hsm(&self, length: usize) -> Result<Vec<u8>> {
        // Fall back to using the system RNG
        use rand::{rng, RngCore};
        let mut rng = rng();
        let mut buffer = vec![0u8; length];
        rng.fill_bytes(&mut buffer);
        Ok(buffer)
    }
    
    /// Placeholder for has HSM capability
    #[cfg(not(feature = "hardware-security"))]
    pub fn has_hw_capability(&self, _capability: u32) -> bool {
        false
    }
    
    //--------------------------------------------------------------
    // Constant-time operation helpers
    //--------------------------------------------------------------
    
    /// Compare two byte slices in constant time
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.is_constant_time_enabled() {
            crate::core::memory::utils::constant_time::constant_time_eq(a, b)
        } else {
            a == b
        }
    }
    
    /// Select between two values in constant time
    pub fn constant_time_select<T>(&self, condition: bool, a: T, b: T) -> T
    where
        T: std::ops::BitXor<Output = T> + Copy,
    {
        if self.is_constant_time_enabled() {
            crate::core::memory::utils::constant_time::constant_time_select(condition, a, b)
        } else {
            if condition { a } else { b }
        }
    }
    
    /// Increment a counter in constant time
    pub fn increment_counter(&self, counter: &mut u32, value: u32) {
        if self.is_constant_time_enabled() {
            crate::core::memory::utils::constant_time::constant_time_increment(counter, value);
        } else {
            *counter = counter.wrapping_add(value);
        }
    }
    
    //--------------------------------------------------------------
    // Memory utilities
    //--------------------------------------------------------------
    
    /// Securely wipe a key from memory
    pub fn wipe_key<T: Zeroize>(&self, key: &mut T) {
        key.zeroize();
    }
    
    /// Zero out sensitive memory regions
    pub fn zeroize_region(&self, region: &mut [u8]) {
        region.zeroize();
    }
    
    /// Lock memory region to prevent swapping
    pub fn lock_memory(&self, ptr: *const u8, size: usize) -> Result<()> {
        if !self.is_memory_locking_enabled() {
            return Ok(());
        }
        
        self.platform.lock_memory(ptr, size)
    }
    
    /// Unlock previously locked memory region
    pub fn unlock_memory(&self, ptr: *const u8, size: usize) -> Result<()> {
        if !self.is_memory_locking_enabled() {
            return Ok(());
        }
        
        self.platform.unlock_memory(ptr, size)
    }
    
    /// Make memory region read-only
    pub fn protect_memory_readonly(&self, ptr: *const u8, size: usize) -> Result<()> {
        if !self.is_read_only_protection_enabled() {
            return Ok(());
        }
        
        self.platform.protect_memory_readonly(ptr, size)
    }
    
    /// Make memory region readable and writable
    pub fn protect_memory_readwrite(&self, ptr: *const u8, size: usize) -> Result<()> {
        if !self.is_read_only_protection_enabled() {
            return Ok(());
        }
        
        self.platform.protect_memory_readwrite(ptr, size)
    }
    
    /// Check if memory protection is working correctly
    pub fn verify_memory_protections(&self) -> bool {
        // Test read-only protection
        let ro_test = self.test_read_only_protection();
        
        // Test zero-on-free
        let zof_test = self.test_zero_on_free();
        
        // Both tests should pass
        ro_test && zof_test
    }
    
    /// Test if read-only memory protection is working
    fn test_read_only_protection(&self) -> bool {
        if !self.is_read_only_protection_enabled() {
            return true;
        }
        
        // Try to create and protect some memory
        let test_value = [1u8, 2, 3, 4];
        let mut protected = ReadOnlyContainer::new(test_value);
        
        // Try to protect it
        let protect_result = protected.protect();
        
        // Make sure we can still read it
        let read_ok = *protected == test_value;
        
        // Unprotect
        protected.unprotect();
        
        protect_result && read_ok
    }
    
    /// Test if zero-on-free is working
    fn test_zero_on_free(&self) -> bool {
        if !self.is_zero_on_free_enabled() {
            return true;
        }
        
        // Create some data we'll verify gets zeroed
        let mut data = vec![42u8; 16];
        
        // Wrap in Zeroizing
        {
            let _wrapped = Zeroizing::new(&mut data);
            // _wrapped goes out of scope here
        }
        
        // Check if data was zeroed
        data.iter().all(|&byte| byte == 0)
    }
}

// Implement SecureMemoryFactory trait for SecureMemoryManager
impl SecureMemoryFactory for SecureMemoryManager {
    fn create_secure_container<T>(&self, value: T) -> SecureContainer<T> {
        let mut container = SecureContainer::new(value);
        
        // Apply current settings
        if self.is_canary_protection_enabled() {
            container.enable_canary();
        } else {
            container.disable_canary();
        }
        
        container
    }
    
    fn create_secure_heap<T>(&self) -> SecureHeap<T> {
        let mut heap = SecureHeap::new();
        
        // Apply current settings
        if self.is_canary_protection_enabled() {
            heap.enable_canary();
        } else {
            heap.disable_canary();
        }
        
        heap
    }
    
    fn create_secure_stack<T, const N: usize>(&self) -> SecureStack<T, N> {
        SecureStack::new()
    }
    
    fn create_readonly_container<T: Sized>(&self, value: T) -> ReadOnlyContainer<T> {
        let container = ReadOnlyContainer::new(value);
        
        // If read-only protection is enabled, protect the memory
        if self.is_read_only_protection_enabled() {
            container.protect();
        }
        
        container
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_manager() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Test creating secure memory through the manager
        let secure_mem = memory_manager.create_secure_container([0u8; 32]);
        
        // Test creating secure vector through the manager
        let secure_vec = memory_manager.create_secure_heap::<u8>();
        
        // Test security settings
        assert_eq!(memory_manager.security_level(), MemorySecurity::Enhanced);
        
        // Change security level
        let mut manager2 = memory_manager;
        manager2.set_security_level(MemorySecurity::Maximum);
        assert_eq!(manager2.security_level(), MemorySecurity::Maximum);
    }
    
    #[test]
    fn test_secure_stack() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Standard);
        
        // Create a 32-byte secure vector (for keys)
        let mut bytes32 = memory_manager.create_secure_stack::<u8, 32>();
        for i in 0..32 {
            bytes32.push(i as u8).unwrap();
        }
        
        assert_eq!(bytes32.len(), 32);
        assert_eq!(bytes32[0], 0);
        assert_eq!(bytes32[31], 31);
    }
    
    #[test]
    fn test_readonly_container() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Create protected memory
        let key_data = [0x42u8; 32];
        let mut key = memory_manager.create_readonly_container(key_data);
        
        // Should start protected if read-only protection is enabled
        if memory_manager.is_read_only_protection_enabled() {
            assert!(key.is_protected());
            
            // We can still read the key
            assert_eq!(*key, [0x42u8; 32]);
            
            // Modifying should automatically unprotect
            key[0] = 0xFF;
            
            // Should no longer be protected
            assert!(!key.is_protected());
            
            // Value should be changed
            assert_eq!(key[0], 0xFF);
        }
    }
    
    #[test]
    fn test_constant_time_operations() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Standard);
        
        // Test constant-time equality comparison
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [5u8, 6, 7, 8];
        
        assert!(memory_manager.constant_time_eq(&a, &b));
        assert!(!memory_manager.constant_time_eq(&a, &c));
        
        // Test constant-time selection
        let result = memory_manager.constant_time_select(true, 42u32, 24u32);
        assert_eq!(result, 42u32);
        
        // Test counter increment
        let mut counter = 5u32;
        memory_manager.increment_counter(&mut counter, 3);
        assert_eq!(counter, 8u32);
    }
    
    #[test]
    fn test_wipe_key() {
        let memory_manager = SecureMemoryManager::default();
        let mut key = vec![42u8; 32];
        
        // All bytes should be 42
        for byte in &key {
            assert_eq!(*byte, 42);
        }
        
        // Wipe the key
        memory_manager.wipe_key(&mut key);
        
        // All bytes should be zeroed
        for byte in &key {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_memory_locking() {
        let memory_manager = SecureMemoryManager::default();
        
        // Enable memory locking
        memory_manager.enable_memory_locking();
        assert!(memory_manager.is_memory_locking_enabled());
        
        // Allocate some memory to test
        let data = vec![0u8; 4096];
        
        // Try to lock the memory
        let result = memory_manager.lock_memory(data.as_ptr(), data.len());
        
        // This might succeed or fail depending on the platform and permissions
        println!("Memory lock result: {:?}", result);
        
        // Unlock the memory
        let unlock_result = memory_manager.unlock_memory(data.as_ptr(), data.len());
        println!("Memory unlock result: {:?}", unlock_result);
    }
}