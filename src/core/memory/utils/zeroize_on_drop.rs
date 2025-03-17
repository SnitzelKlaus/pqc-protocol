/*!
Zero-on-drop wrapper for secure memory in the PQC protocol.

This module provides a wrapper type that automatically zeroizes memory
when it goes out of scope, ensuring that sensitive cryptographic material
is not left in memory.
*/

use zeroize::Zeroize;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

/// A wrapper that automatically zeroizes its contents when dropped.
///
/// This ensures that sensitive cryptographic material (like keys, seeds, etc.)
/// is properly erased from memory when it's no longer needed, reducing the
/// risk of key material being exposed in a memory dump.
pub struct ZeroizeOnDrop<T: Zeroize> {
    /// Inner value that will be zeroized on drop
    inner: T,
    /// Flag indicating if zeroizing is enabled
    enabled: AtomicBool,
}

impl<T: Zeroize> ZeroizeOnDrop<T> {
    /// Create a new ZeroizeOnDrop wrapper around a value.
    pub fn new(value: T) -> Self {
        Self { 
            inner: value,
            enabled: AtomicBool::new(true),
        }
    }

    /// Consume the wrapper and return the inner value without zeroizing.
    ///
    /// # Security Warning
    ///
    /// This method is intended for cases where you need to transfer ownership
    /// of the sensitive data to another component or function. Be careful using
    /// this method as it bypasses the automatic zeroization.
    pub fn into_inner(self) -> T {
        // Disable zeroizing before extracting the inner value
        self.set_zeroizing_enabled(false);
        
        // Use ManuallyDrop to prevent the drop implementation from running
        let inner = std::mem::ManuallyDrop::new(self);
        
        // Safety: we're transferring ownership without running the destructor
        unsafe { std::ptr::read(&inner.inner) }
    }
    
    /// Enable or disable automatic zeroizing on drop
    pub fn set_zeroizing_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// Check if automatic zeroizing is enabled
    pub fn is_zeroizing_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    /// Explicitly zeroize the inner value
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Deref for ZeroizeOnDrop<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for ZeroizeOnDrop<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for ZeroizeOnDrop<T> {
    fn drop(&mut self) {
        if self.is_zeroizing_enabled() {
            self.inner.zeroize();
        }
    }
}

impl<T: Zeroize + Clone> Clone for ZeroizeOnDrop<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            enabled: AtomicBool::new(self.is_zeroizing_enabled()),
        }
    }
}

impl<T: Zeroize + fmt::Debug> fmt::Debug for ZeroizeOnDrop<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroizeOnDrop")
            .field("inner", &self.inner)
            .field("zeroizing_enabled", &self.is_zeroizing_enabled())
            .finish()
    }
}

impl<T: Zeroize + Default> Default for ZeroizeOnDrop<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for ZeroizeOnDrop<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Zeroize + Eq> Eq for ZeroizeOnDrop<T> {}

/// Helper trait for types that should be zeroized on drop
pub trait AutoZeroize: Sized + Zeroize {
    /// Wrap this value in a ZeroizeOnDrop container
    fn auto_zeroize(self) -> ZeroizeOnDrop<Self> {
        ZeroizeOnDrop::new(self)
    }
}

// Implement AutoZeroize for common types that should be zeroized
impl<T: Zeroize> AutoZeroize for T {}

#[cfg(test)]
mod tests {
    use super::*;

    // Custom type for testing
    #[derive(Debug, PartialEq)]
    struct SensitiveData {
        data: Vec<u8>,
    }
    
    impl Zeroize for SensitiveData {
        fn zeroize(&mut self) {
            for byte in &mut self.data {
                *byte = 0;
            }
        }
    }
    
    impl Clone for SensitiveData {
        fn clone(&self) -> Self {
            Self { data: self.data.clone() }
        }
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Create a wrapper around a custom type
        let data = SensitiveData { data: vec![1, 2, 3, 4] };
        let mut wrapper = ZeroizeOnDrop::new(data);
        
        // Modify the data
        wrapper.data[0] = 42;
        
        // Create a clone to check that zeroizing works independently
        let wrapper_clone = wrapper.clone();
        
        // Explicitly drop wrapper_clone
        drop(wrapper_clone);
        
        // wrapper should still be valid
        assert_eq!(wrapper.data[0], 42);
        
        // Explicitly zeroize wrapper
        wrapper.zeroize();
        
        // Data should be zeroed
        assert_eq!(wrapper.data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_into_inner() {
        let data = SensitiveData { data: vec![1, 2, 3, 4] };
        let wrapper = ZeroizeOnDrop::new(data);
        
        // Extract the inner value
        let extracted = wrapper.into_inner();
        
        // Verify the data wasn't zeroized
        assert_eq!(extracted.data, vec![1, 2, 3, 4]);
    }
    
    #[test]
    fn test_disable_zeroizing() {
        let data = vec![1u8, 2, 3, 4];
        let mut cloned_data = data.clone();
        
        {
            let wrapper = ZeroizeOnDrop::new(&mut cloned_data);
            
            // Disable zeroizing
            wrapper.set_zeroizing_enabled(false);
            
            // wrapper is dropped here, but shouldn't zeroize
        }
        
        // Data should not be zeroed
        assert_eq!(cloned_data, vec![1, 2, 3, 4]);
        
        {
            let wrapper = ZeroizeOnDrop::new(&mut cloned_data);
            
            // Leave zeroizing enabled
            assert!(wrapper.is_zeroizing_enabled());
            
            // wrapper is dropped here, should zeroize
        }
        
        // Data should be zeroed
        assert_eq!(cloned_data, vec![0, 0, 0, 0]);
    }
    
    #[test]
    fn test_auto_zeroize() {
        let data = vec![1u8, 2, 3, 4];
        let auto_zeroize_data = data.clone().auto_zeroize();
        
        // Check that we can access the data
        assert_eq!(*auto_zeroize_data, vec![1, 2, 3, 4]);
    }
}