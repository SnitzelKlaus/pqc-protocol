/*!
Memory security management for cryptographic sessions.

This module provides enhanced memory security features for session objects,
allowing for secure handling of sensitive cryptographic materials.
*/

use crate::core::{
    error::Result,
    memory::{SecureMemory, SecureVec, Zeroize, secure_zero_memory},
    crypto::{
        key_exchange::KyberSecretKey,
        auth::DilithiumSecretKey,
    },
};

use std::sync::atomic::{AtomicBool, Ordering};

/// Memory security level options for session data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySecurity {
    /// Standard security: basic protections
    Standard,
    /// Enhanced security: additional protections and canary values
    Enhanced,
    /// Maximum security: all protections enabled, read-only when not in use
    Maximum,
}

impl Default for MemorySecurity {
    fn default() -> Self {
        MemorySecurity::Standard
    }
}

/// Manages secure memory for a session
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
}

impl SecureMemoryManager {
    /// Create a new secure memory manager with the specified security level
    pub fn new(level: MemorySecurity) -> Self {
        let manager = Self {
            level,
            auto_erase: true,
            memory_locking: AtomicBool::new(true),
            canary_protection: AtomicBool::new(true),
            zero_on_free: AtomicBool::new(true),
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
    
    /// Create a secure memory container for sensitive data
    pub fn secure_memory<T>(&self, value: T) -> SecureMemory<T> {
        SecureMemory::new(value)
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
    
    /// Securely wipe a key from memory
    pub fn wipe_key<T: Zeroize>(&self, key: &mut T) {
        key.zeroize();
    }
    
    /// Securely create a Kyber secret key 
    pub fn create_kyber_secret_key(&self, data: &[u8]) -> Result<SecureMemory<KyberSecretKey>> {
        let secret_key = pqcrypto_kyber::kyber768::SecretKey::from_bytes(data)?;
        Ok(self.secure_memory(secret_key))
    }
    
    /// Securely create a Dilithium secret key
    pub fn create_dilithium_secret_key(&self, data: &[u8]) -> Result<SecureMemory<DilithiumSecretKey>> {
        let secret_key = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(data)?;
        Ok(self.secure_memory(secret_key))
    }
    
    /// Apply current security settings to an existing SecureMemory container
    pub fn apply_settings_to_memory<T>(&self, _memory: &mut SecureMemory<T>) {
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
}

/// SecureSession trait for applying memory security to sessions
pub trait SecureSession {
    /// Get memory security manager
    fn memory_manager(&self) -> &SecureMemoryManager;
    
    /// Get mutable reference to memory security manager
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager;
    
    /// Set memory security level
    fn set_memory_security_level(&mut self, level: MemorySecurity) {
        self.memory_manager_mut().set_security_level(level);
    }
    
    /// Get current memory security level
    fn memory_security_level(&self) -> MemorySecurity {
        self.memory_manager().security_level()
    }
    
    /// Enable memory locking
    fn enable_memory_locking(&mut self) {
        self.memory_manager().enable_memory_locking();
    }
    
    /// Disable memory locking
    fn disable_memory_locking(&mut self) {
        self.memory_manager().disable_memory_locking();
    }
    
    /// Enable canary protection
    fn enable_canary_protection(&mut self) {
        self.memory_manager().enable_canary_protection();
    }
    
    /// Disable canary protection
    fn disable_canary_protection(&mut self) {
        self.memory_manager().disable_canary_protection();
    }
    
    /// Check if memory is secure
    fn is_memory_secure(&self) -> bool {
        let manager = self.memory_manager();
        manager.is_memory_locking_enabled() &&
        manager.is_canary_protection_enabled() &&
        manager.is_zero_on_free_enabled()
    }
    
    /// Erase sensitive memory
    fn erase_sensitive_memory(&mut self);
}

/// Implementation of memory security for PqcSession
impl SecureSession for crate::core::session::PqcSession {
    fn memory_manager(&self) -> &SecureMemoryManager {
        // Access the memory manager - in a real implementation
        // this would be an actual field in the PqcSession struct
        // For now, we'll create a dummy manager each time
        // This is just for demonstration and should be replaced
        static DUMMY_MANAGER: std::sync::OnceLock<SecureMemoryManager> = std::sync::OnceLock::new();
        DUMMY_MANAGER.get_or_init(|| SecureMemoryManager::default())
    }
    
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager {
        // This is a placeholder - in a real implementation we would
        // return a mutable reference to the actual memory manager
        // This implementation is not thread-safe and just for
        // demonstration purposes
        static mut DUMMY_MANAGER: Option<SecureMemoryManager> = None;
        unsafe {
            if DUMMY_MANAGER.is_none() {
                DUMMY_MANAGER = Some(SecureMemoryManager::default());
            }
            DUMMY_MANAGER.as_mut().unwrap()
        }
    }
    
    fn erase_sensitive_memory(&mut self) {
        // This would erase all sensitive key material in the session
        // For a real implementation, we would access the actual
        // fields of the session and zero them out
        
        // For example:
        // if let Some(ref mut key) = self.kyber_secret_key {
        //     self.memory_manager().wipe_key(key);
        // }
        
        // This is just a demonstration stub
    }
}

/// Extension for AsyncPqcClient and AsyncPqcServer
impl<T: std::ops::DerefMut<Target = crate::core::session::PqcSession>> SecureSession for std::sync::Mutex<T> {
    fn memory_manager(&self) -> &SecureMemoryManager {
        // This is a placeholder - in a real implementation we would
        // access the memory manager through the mutex
        static DUMMY_MANAGER: std::sync::OnceLock<SecureMemoryManager> = std::sync::OnceLock::new();
        DUMMY_MANAGER.get_or_init(|| SecureMemoryManager::default())
    }
    
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager {
        // This is a placeholder - in a real implementation we would
        // access the memory manager through the mutex
        static mut DUMMY_MANAGER: Option<SecureMemoryManager> = None;
        unsafe {
            if DUMMY_MANAGER.is_none() {
                DUMMY_MANAGER = Some(SecureMemoryManager::default());
            }
            DUMMY_MANAGER.as_mut().unwrap()
        }
    }
    
    fn erase_sensitive_memory(&mut self) {
        // In a real implementation, we would lock the mutex
        // and call erase_sensitive_memory on the inner session
        
        // This is just a demonstration stub
        if let Ok(mut session) = self.lock() {
            session.deref_mut().erase_sensitive_memory();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_levels() {
        let mut manager = SecureMemoryManager::default();
        assert_eq!(manager.security_level(), MemorySecurity::Standard);
        
        manager.set_security_level(MemorySecurity::Enhanced);
        assert_eq!(manager.security_level(), MemorySecurity::Enhanced);
        
        manager.set_security_level(MemorySecurity::Maximum);
        assert_eq!(manager.security_level(), MemorySecurity::Maximum);
    }
    
    #[test]
    fn test_memory_locking() {
        let manager = SecureMemoryManager::default();
        
        // Default should be enabled
        assert!(manager.is_memory_locking_enabled());
        
        manager.disable_memory_locking();
        assert!(!manager.is_memory_locking_enabled());
        
        manager.enable_memory_locking();
        assert!(manager.is_memory_locking_enabled());
    }
    
    #[test]
    fn test_secure_memory_creation() {
        let manager = SecureMemoryManager::default();
        let secure_memory = manager.secure_memory([0u8; 32]);
        
        for byte in secure_memory.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_vec_creation() {
        let manager = SecureMemoryManager::default();
        let mut secure_vec = manager.secure_vec_from_vec(vec![1, 2, 3, 4, 5]);
        
        assert_eq!(secure_vec.len(), 5);
        assert_eq!(secure_vec[0], 1);
        
        secure_vec.clear();
        assert_eq!(secure_vec.len(), 0);
    }
    
    #[test]
    fn test_secure_session_trait() {
        let mut session = crate::core::session::PqcSession::new().unwrap();
        
        // Test the default security level
        assert_eq!(session.memory_security_level(), MemorySecurity::Standard);
        
        // Change the security level
        session.set_memory_security_level(MemorySecurity::Enhanced);
        
        // Test memory locking
        assert!(session.is_memory_secure());
        session.disable_memory_locking();
        assert!(!session.is_memory_secure());
        session.enable_memory_locking();
        assert!(session.is_memory_secure());
        
        // Test erasing memory
        session.erase_sensitive_memory();
        
        // No assertion needed - we just make sure it doesn't crash
    }
}