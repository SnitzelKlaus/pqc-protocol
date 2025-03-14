/*!
Enhanced secure memory manager for the PQC protocol.

This module extends the existing memory manager with improved security features:
- ZeroizeOnDrop for automatic zeroization
- Heapless vectors to avoid heap allocation risks
- Protected memory using mprotect for read-only after initialization
- Hardware security module integration
- Constant-time operations to prevent timing attacks
*/

use std::sync::atomic::{AtomicBool, Ordering};
use crate::core::memory::memory_security::MemorySecurity;
use crate::core::memory::zeroize::{Zeroize, secure_zero_memory};
use crate::core::memory::secure_memory::SecureMemory;
use crate::core::memory::secure_vec::SecureVec;
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;
use crate::core::memory::heapless_vec::{SecureHeaplessVec, SecureVec32, SecureVec64};
use crate::core::memory::protected_memory::{ProtectedMemory, ProtectedKey32};
use crate::core::security::hardware_security::{HardwareSecurityManager, HardwareSecurityCapability};
use crate::core::security::constant_time;
use crate::core::error::Result;

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
    
    /// Hardware security manager for TPM, SGX, etc.
    hw_security: Option<HardwareSecurityManager>,
    
    /// Whether to use constant-time operations
    use_constant_time: AtomicBool,
    
    /// Whether to use read-only memory protection
    use_read_only_protection: AtomicBool,
}

impl SecureMemoryManager {
    /// Create a new secure memory manager with the specified security level
    pub fn new(level: MemorySecurity) -> Self {
        // Initialize hardware security if available
        let hw_security = HardwareSecurityManager::new();
        let has_hw_security = hw_security.is_available();
        
        let manager = Self {
            level,
            auto_erase: true,
            
            #[cfg(feature = "memory-lock")]
            memory_locking: AtomicBool::new(true),
            #[cfg(not(feature = "memory-lock"))]
            memory_locking: AtomicBool::new(false),
            
            #[cfg(feature = "memory-canary")]
            canary_protection: AtomicBool::new(true),
            #[cfg(not(feature = "memory-canary"))]
            canary_protection: AtomicBool::new(false),
            
            #[cfg(feature = "memory-zero")]
            zero_on_free: AtomicBool::new(true),
            #[cfg(not(feature = "memory-zero"))]
            zero_on_free: AtomicBool::new(false),
            
            use_hardware_security: AtomicBool::new(has_hw_security),
            hw_security: Some(hw_security),
            
            use_constant_time: AtomicBool::new(true),
            
            use_read_only_protection: AtomicBool::new(true),
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
    }
    
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
    
    /// Get the hardware security manager, if available
    pub fn hardware_security_manager(&self) -> Option<&HardwareSecurityManager> {
        self.hw_security.as_ref()
    }
    
    //--------------------------------------------------------------
    // Secure memory creation functions
    //--------------------------------------------------------------
    
    /// Create a secure memory container for sensitive data
    pub fn secure_memory<T>(&self, value: T) -> SecureMemory<T> {
        SecureMemory::new(value)
    }
    
    /// Create a secure memory container with auto-zeroing
    pub fn zeroizing_memory<T: Zeroize>(&self, value: T) -> ZeroizeOnDrop<T> {
        ZeroizeOnDrop::new(value)
    }
    
    /// Create a protected memory container that can be made read-only
    pub fn protected_memory<T: Sized>(&self, value: T) -> ProtectedMemory<T> {
        let mut memory = ProtectedMemory::new(value);
        
        // If read-only protection is enabled, protect the memory
        if self.is_read_only_protection_enabled() {
            memory.protect();
        }
        
        memory
    }
    
    /// Create a secure vector container
    pub fn secure_vec<T>(&self) -> SecureVec<T> {
        SecureVec::new()
    }
    
    /// Create a secure vector with capacity
    pub fn secure_vec_with_capacity<T>(&self, capacity: usize) -> SecureVec<T> {
        SecureVec::with_capacity(capacity)
    }
    
    /// Create a secure vector from an existing vector
    pub fn secure_vec_from_vec<T>(&self, vec: Vec<T>) -> SecureVec<T> {
        SecureVec::from_vec(vec)
    }
    
    /// Create a secure heapless vector (stack-allocated)
    pub fn secure_heapless_vec<T, const N: usize>(&self) -> SecureHeaplessVec<T, N> {
        SecureHeaplessVec::new()
    }
    
    /// Create a 32-byte secure heapless vector (for 256-bit keys)
    pub fn secure_bytes32(&self) -> SecureVec32 {
        SecureVec32::new()
    }
    
    /// Create a 64-byte secure heapless vector (for 512-bit keys)
    pub fn secure_bytes64(&self) -> SecureVec64 {
        SecureVec64::new()
    }
    
    /// Create a protected 32-byte key
    pub fn protected_key32(&self, key_data: [u8; 32]) -> ProtectedKey32 {
        let mut key = ProtectedMemory::new(key_data);
        
        // If read-only protection is enabled, protect the memory
        if self.is_read_only_protection_enabled() {
            key.protect();
        }
        
        key
    }
    
    //--------------------------------------------------------------
    // Hardware security functions
    //--------------------------------------------------------------
    
    /// Store a key in hardware security module
    pub fn store_key_in_hsm(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        if !self.is_hardware_security_enabled() {
            return Ok(());
        }
        
        if let Some(hw) = &self.hw_security {
            hw.store_key(key_id, key_data)
        } else {
            Ok(())
        }
    }
    
    /// Retrieve a key from hardware security module
    pub fn retrieve_key_from_hsm(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        if !self.is_hardware_security_enabled() {
            return Ok(None);
        }
        
        if let Some(hw) = &self.hw_security {
            hw.retrieve_key(key_id)
        } else {
            Ok(None)
        }
    }
    
    /// Sign data using a key in the hardware security module
    pub fn sign_with_hsm(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        if !self.is_hardware_security_enabled() {
            return Err(crate::core::error::Error::Internal(
                "Hardware security not enabled".to_string()
            ));
        }
        
        if let Some(hw) = &self.hw_security {
            hw.sign_data(key_id, data)
        } else {
            Err(crate::core::error::Error::Internal(
                "Hardware security module not available".to_string()
            ))
        }
    }
    
    /// Generate random data using hardware security module
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
    // Constant-time operation helpers
    //--------------------------------------------------------------
    
    /// Compare two byte slices in constant time
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.is_constant_time_enabled() {
            constant_time::constant_time_eq(a, b)
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
            constant_time::constant_time_select(condition, a, b)
        } else {
            if condition { a } else { b }
        }
    }
    
    /// Increment a counter in constant time
    pub fn increment_counter(&self, counter: &mut u32, value: u32) {
        if self.is_constant_time_enabled() {
            constant_time::constant_time_increment(counter, value);
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
    
    /// Apply current security settings to an existing SecureMemory container
    pub fn apply_settings_to_memory<T>(&self, memory: &mut SecureMemory<T>) {
        // This is a placeholder - in a real implementation, we would
        // modify the security settings of the memory container
    }
    
    /// Apply current security settings to an existing SecureVec container
    pub fn apply_settings_to_vec<T>(&self, vec: &mut SecureVec<T>) {
        if self.is_canary_protection_enabled() {
            vec.enable_canary();
        } else {
            vec.disable_canary();
        }
    }
    
    /// Zero out sensitive memory regions
    pub fn zeroize_region(&self, region: &mut [u8]) {
        secure_zero_memory(region);
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
        let mut protected = ProtectedMemory::new(test_value);
        
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
        let data_ptr = data.as_ptr() as usize;
        
        // Wrap in ZeroizeOnDrop
        {
            let _wrapped = ZeroizeOnDrop::new(&mut data);
            // _wrapped goes out of scope here
        }
        
        // Check if data was zeroed
        data.iter().all(|&byte| byte == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_manager() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Test creating secure memory through the manager
        let secure_mem = memory_manager.secure_memory([0u8; 32]);
        
        #[cfg(feature = "memory-lock")]
        assert!(secure_mem.is_locked());
        
        // Test creating secure vector through the manager
        let secure_vec = memory_manager.secure_vec_from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(secure_vec[0], 1);
        
        // Test security settings
        #[cfg(feature = "memory-lock")]
        assert!(memory_manager.is_memory_locking_enabled());
        
        #[cfg(feature = "memory-canary")]
        assert!(memory_manager.is_canary_protection_enabled());
        
        #[cfg(feature = "memory-zero")]
        assert!(memory_manager.is_zero_on_free_enabled());
        
        // Test security level
        assert_eq!(memory_manager.security_level(), MemorySecurity::Enhanced);
    }
    
    #[test]
    fn test_heapless_vectors() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Standard);
        
        // Create a 32-byte secure vector (for keys)
        let mut bytes32 = memory_manager.secure_bytes32();
        for i in 0..32 {
            bytes32.push(i as u8).unwrap();
        }
        
        assert_eq!(bytes32.len(), 32);
        assert_eq!(bytes32[0], 0);
        assert_eq!(bytes32[31], 31);
        
        // Create a 64-byte secure vector (for signatures)
        let mut bytes64 = memory_manager.secure_bytes64();
        for i in 0..64 {
            bytes64.push(i as u8).unwrap();
        }
        
        assert_eq!(bytes64.len(), 64);
    }
    
    #[test]
    fn test_zeroizing_memory() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Standard);
        
        // Test with a simple array
        let original = [1u8, 2, 3, 4, 5];
        let mut data = original.clone();
        
        {
            let mut zeroizing = memory_manager.zeroizing_memory(&mut data);
            // Modify the data
            zeroizing[0] = 42;
            // zeroizing is dropped here
        }
        
        // Data should be zeroed out
        assert_eq!(data, [0, 0, 0, 0, 0]);
    }
    
    #[test]
    fn test_protected_memory() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Create protected memory
        let key_data = [0x42u8; 32];
        let mut key = memory_manager.protected_key32(key_data);
        
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
    fn test_hardware_security() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Maximum);
        
        // Check if hardware security is available
        println!("Hardware security enabled: {}", memory_manager.is_hardware_security_enabled());
        
        // If hardware security is available, test it
        if memory_manager.is_hardware_security_enabled() {
            if let Some(hw) = memory_manager.hardware_security_manager() {
                println!("Available HSMs: {:?}", hw.available_hsm_types());
                
                // Check capabilities
                let has_rng = memory_manager.has_hw_capability(HardwareSecurityCapability::RandomGeneration);
                println!("Has hardware RNG: {}", has_rng);
                
                // Generate random data using HSM
                if has_rng {
                    let random = memory_manager.generate_random_with_hsm(32).unwrap();
                    assert_eq!(random.len(), 32);
                }
            }
        }
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
}