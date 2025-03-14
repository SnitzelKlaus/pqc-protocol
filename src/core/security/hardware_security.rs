/*!
Hardware security module for the PQC protocol.

This module provides interfaces for utilizing hardware security modules (HSMs),
Trusted Platform Modules (TPMs), and Intel SGX for secure key storage and
cryptographic operations.
*/

use std::fmt;
use std::sync::Arc;
use crate::core::error::{Result, Error};

/// Represents a hardware security capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareSecurityCapability {
    /// Secure key storage
    KeyStorage,
    /// Hardware encryption
    Encryption,
    /// Hardware random number generation
    RandomGeneration,
    /// Hardware key generation
    KeyGeneration,
    /// Hardware signing
    Signing,
}

/// Interface for hardware security modules
pub trait HardwareSecurityModule: Send + Sync {
    /// Returns the type of HSM
    fn hsm_type(&self) -> &str;
    
    /// Check if a specific capability is supported
    fn supports(&self, capability: HardwareSecurityCapability) -> bool;
    
    /// Store a key in the HSM
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()>;
    
    /// Retrieve a key from the HSM
    fn retrieve_key(&self, key_id: &str) -> Result<Option<Vec<u8>>>;
    
    /// Delete a key from the HSM
    fn delete_key(&self, key_id: &str) -> Result<bool>;
    
    /// Sign data using a key stored in the HSM
    fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Encrypt data using a key stored in the HSM
    fn encrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data using a key stored in the HSM
    fn decrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Generate secure random bytes
    fn generate_random(&self, length: usize) -> Result<Vec<u8>>;
    
    /// Generate a new key in the HSM
    fn generate_key(&self, key_id: &str, key_type: &str, exportable: bool) -> Result<()>;
}

/// Manager for hardware security modules
#[derive(Clone)]
pub struct HardwareSecurityManager {
    /// The active HSM, if available
    active_hsm: Option<Arc<dyn HardwareSecurityModule>>,
    /// List of available HSMs
    available_hsms: Vec<Arc<dyn HardwareSecurityModule>>,
}

impl HardwareSecurityManager {
    /// Create a new hardware security manager
    pub fn new() -> Self {
        let available_hsms = Self::detect_available_hsms();
        let active_hsm = available_hsms.first().cloned();
        
        Self {
            active_hsm,
            available_hsms,
        }
    }
    
    /// Detect available hardware security modules
    fn detect_available_hsms() -> Vec<Arc<dyn HardwareSecurityModule>> {
        let mut hsms = Vec::new();
        
        // Try to initialize TPM if available
        if let Ok(tpm) = TpmModule::new() {
            hsms.push(Arc::new(tpm));
        }
        
        // Try to initialize SGX if available
        #[cfg(feature = "sgx")]
        if let Ok(sgx) = SgxModule::new() {
            hsms.push(Arc::new(sgx));
        }
        
        // Add more HSM types here as needed
        
        // If no hardware HSMs are available, add a software fallback
        if hsms.is_empty() {
            hsms.push(Arc::new(SoftwareHsmFallback::new()));
        }
        
        hsms
    }
    
    /// Check if hardware security is available
    pub fn is_available(&self) -> bool {
        self.active_hsm.is_some()
    }
    
    /// Get a reference to the active HSM
    pub fn active_hsm(&self) -> Option<&Arc<dyn HardwareSecurityModule>> {
        self.active_hsm.as_ref()
    }
    
    /// Set the active HSM by index
    pub fn set_active_hsm(&mut self, index: usize) -> Result<()> {
        if index < self.available_hsms.len() {
            self.active_hsm = Some(self.available_hsms[index].clone());
            Ok(())
        } else {
            Err(Error::Internal(format!("HSM index out of bounds: {}", index)))
        }
    }
    
    /// Set the active HSM by type
    pub fn set_active_hsm_by_type(&mut self, hsm_type: &str) -> Result<()> {
        for (i, hsm) in self.available_hsms.iter().enumerate() {
            if hsm.hsm_type() == hsm_type {
                return self.set_active_hsm(i);
            }
        }
        
        Err(Error::Internal(format!("HSM type not found: {}", hsm_type)))
    }
    
    /// Get list of available HSM types
    pub fn available_hsm_types(&self) -> Vec<String> {
        self.available_hsms
            .iter()
            .map(|hsm| hsm.hsm_type().to_string())
            .collect()
    }
    
    /// Store a key in the active HSM
    pub fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        if let Some(hsm) = &self.active_hsm {
            hsm.store_key(key_id, key_data)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Retrieve a key from the active HSM
    pub fn retrieve_key(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        if let Some(hsm) = &self.active_hsm {
            hsm.retrieve_key(key_id)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Delete a key from the active HSM
    pub fn delete_key(&self, key_id: &str) -> Result<bool> {
        if let Some(hsm) = &self.active_hsm {
            hsm.delete_key(key_id)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Sign data using a key stored in the active HSM
    pub fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(hsm) = &self.active_hsm {
            hsm.sign_data(key_id, data)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Encrypt data using a key stored in the active HSM
    pub fn encrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(hsm) = &self.active_hsm {
            hsm.encrypt_data(key_id, data)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Decrypt data using a key stored in the active HSM
    pub fn decrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(hsm) = &self.active_hsm {
            hsm.decrypt_data(key_id, data)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Generate secure random bytes
    pub fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        if let Some(hsm) = &self.active_hsm {
            hsm.generate_random(length)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Generate a new key in the active HSM
    pub fn generate_key(&self, key_id: &str, key_type: &str, exportable: bool) -> Result<()> {
        if let Some(hsm) = &self.active_hsm {
            hsm.generate_key(key_id, key_type, exportable)
        } else {
            Err(Error::Internal("No active HSM available".to_string()))
        }
    }
    
    /// Check if a specific capability is supported by the active HSM
    pub fn supports(&self, capability: HardwareSecurityCapability) -> bool {
        self.active_hsm
            .as_ref()
            .map_or(false, |hsm| hsm.supports(capability))
    }
}

impl Default for HardwareSecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HardwareSecurityManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HardwareSecurityManager")
            .field("active_hsm", &self.active_hsm.as_ref().map(|h| h.hsm_type()))
            .field("available_hsms", &self.available_hsm_types())
            .finish()
    }
}

//--------------------------------------------------------------------
// Implementation for Trusted Platform Module (TPM)
//--------------------------------------------------------------------

/// TPM (Trusted Platform Module) implementation
pub struct TpmModule {
    /// Internal TPM context
    context: Option<tpm2_client::Context>,
}

impl TpmModule {
    /// Create a new TPM module
    pub fn new() -> Result<Self> {
        // Attempt to initialize TPM
        let context = match tpm2_client::Context::new() {
            Ok(ctx) => Some(ctx),
            Err(e) => {
                eprintln!("TPM initialization failed: {:?}", e);
                None
            }
        };
        
        Ok(Self { context })
    }
    
    /// Check if TPM is available
    pub fn is_available(&self) -> bool {
        self.context.is_some()
    }
}

impl HardwareSecurityModule for TpmModule {
    fn hsm_type(&self) -> &str {
        "TPM"
    }
    
    fn supports(&self, capability: HardwareSecurityCapability) -> bool {
        if !self.is_available() {
            return false;
        }
        
        match capability {
            HardwareSecurityCapability::KeyStorage => true,
            HardwareSecurityCapability::Encryption => true,
            HardwareSecurityCapability::RandomGeneration => true,
            HardwareSecurityCapability::KeyGeneration => true,
            HardwareSecurityCapability::Signing => true,
        }
    }
    
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM key storage operations would go here
        // This is a simplified implementation
        
        Ok(())
    }
    
    fn retrieve_key(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM key retrieval would go here
        // For sensitive keys, TPM typically doesn't allow export
        
        // Return a dummy key for now
        Ok(Some(vec![0u8; 32]))
    }
    
    fn delete_key(&self, key_id: &str) -> Result<bool> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM key deletion would go here
        
        Ok(true)
    }
    
    fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM signing operation would go here
        
        // Return a dummy signature for now
        Ok(vec![0u8; 64])
    }
    
    fn encrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM encryption would go here
        
        // Return the data as-is for now
        Ok(data.to_vec())
    }
    
    fn decrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM decryption would go here
        
        // Return the data as-is for now
        Ok(data.to_vec())
    }
    
    fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM random generation would go here
        
        // Return dummy random data for now
        Ok(vec![0u8; length])
    }
    
    fn generate_key(&self, key_id: &str, key_type: &str, exportable: bool) -> Result<()> {
        let ctx = self.context.as_ref().ok_or_else(|| {
            Error::Internal("TPM not available".to_string())
        })?;
        
        // TPM key generation would go here
        
        Ok(())
    }
}

//--------------------------------------------------------------------
// Software fallback for when hardware security is not available
//--------------------------------------------------------------------

/// Software fallback HSM for when hardware security is not available
pub struct SoftwareHsmFallback {
    /// In-memory key storage
    keys: std::collections::HashMap<String, Vec<u8>>,
}

impl SoftwareHsmFallback {
    /// Create a new software HSM fallback
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }
}

impl Default for SoftwareHsmFallback {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareSecurityModule for SoftwareHsmFallback {
    fn hsm_type(&self) -> &str {
        "Software-Fallback"
    }
    
    fn supports(&self, capability: HardwareSecurityCapability) -> bool {
        match capability {
            HardwareSecurityCapability::KeyStorage => true,
            HardwareSecurityCapability::Encryption => true,
            HardwareSecurityCapability::RandomGeneration => true,
            HardwareSecurityCapability::KeyGeneration => true,
            HardwareSecurityCapability::Signing => true,
        }
    }
    
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<()> {
        // In a real implementation, this would use secure memory techniques
        // For now, just clone the key data
        let mut keys = self.keys.clone();
        keys.insert(key_id.to_string(), key_data.to_vec());
        
        Ok(())
    }
    
    fn retrieve_key(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.keys.get(key_id).cloned())
    }
    
    fn delete_key(&self, key_id: &str) -> Result<bool> {
        let mut keys = self.keys.clone();
        Ok(keys.remove(key_id).is_some())
    }
    
    fn sign_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Simple HMAC signing as a fallback
        if let Some(key) = self.keys.get(key_id) {
            use sha2::Sha256;
            use hmac::{Hmac, Mac};
            
            type HmacSha256 = Hmac<Sha256>;
            
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|_| Error::Internal("HMAC initialization failed".to_string()))?;
            
            mac.update(data);
            
            let result = mac.finalize();
            Ok(result.into_bytes().to_vec())
        } else {
            Err(Error::Internal(format!("Key not found: {}", key_id)))
        }
    }
    
    fn encrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Simple XOR encryption as a fallback (NOT secure!)
        if let Some(key) = self.keys.get(key_id) {
            let mut result = Vec::with_capacity(data.len());
            
            for (i, byte) in data.iter().enumerate() {
                result.push(byte ^ key[i % key.len()]);
            }
            
            Ok(result)
        } else {
            Err(Error::Internal(format!("Key not found: {}", key_id)))
        }
    }
    
    fn decrypt_data(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Simple XOR decryption as a fallback (NOT secure!)
        self.encrypt_data(key_id, data) // XOR is symmetric
    }
    
    fn generate_random(&self, length: usize) -> Result<Vec<u8>> {
        // Use system RNG as a fallback
        use rand::{thread_rng, RngCore};
        
        let mut rng = thread_rng();
        let mut buffer = vec![0u8; length];
        rng.fill_bytes(&mut buffer);
        
        Ok(buffer)
    }
    
    fn generate_key(&self, key_id: &str, key_type: &str, exportable: bool) -> Result<()> {
        // Generate a random key as a fallback
        let length = match key_type {
            "AES-128" => 16,
            "AES-256" => 32,
            "HMAC" => 64,
            _ => 32, // Default
        };
        
        let key = self.generate_random(length)?;
        self.store_key(key_id, &key)
    }
}

/// Module-level unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hsm_manager() {
        let manager = HardwareSecurityManager::new();
        
        // Test HSM detection
        println!("Available HSMs: {:?}", manager.available_hsm_types());
        
        // There should always be at least the software fallback
        assert!(!manager.available_hsm_types().is_empty());
        
        // Check if an HSM is active
        assert!(manager.is_available());
    }
    
    #[test]
    fn test_software_fallback() {
        let hsm = SoftwareHsmFallback::new();
        
        // Test key generation
        hsm.generate_key("test-key", "AES-256", true).unwrap();
        
        // Generate some random data
        let data = hsm.generate_random(64).unwrap();
        assert_eq!(data.len(), 64);
        
        // Test signing
        let signature = hsm.sign_data("test-key", &data).unwrap();
        assert!(!signature.is_empty());
        
        // Test encryption/decryption
        let encrypted = hsm.encrypt_data("test-key", &data).unwrap();
        let decrypted = hsm.decrypt_data("test-key", &encrypted).unwrap();
        assert_eq!(data, decrypted);
    }
}