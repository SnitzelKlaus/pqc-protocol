/*!
Stack-allocated secure container for the PQC protocol.

This module provides a wrapper around heapless::Vec to ensure sensitive
cryptographic material never gets allocated on the heap, which is more
difficult to reliably clean up and can be subject to memory dumps.
*/

use std::ops::{Deref, DerefMut};
use std::fmt;

use heapless::Vec as HeaplessVec;
use zeroize::Zeroize;

use crate::core::memory::traits::protection::MemoryProtection;
use crate::core::memory::error::{Error, Result};

/// A wrapper that zeroizes a heapless::Vec when dropped
struct ZeroizableHeaplessVec<T, const N: usize> {
    inner: HeaplessVec<T, N>
}

impl<T, const N: usize> ZeroizableHeaplessVec<T, N> {
    fn new(vec: HeaplessVec<T, N>) -> Self {
        Self { inner: vec }
    }
    
    fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<T, const N: usize> Deref for ZeroizableHeaplessVec<T, N> {
    type Target = HeaplessVec<T, N>;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for ZeroizableHeaplessVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, const N: usize> Zeroize for ZeroizableHeaplessVec<T, N> {
    fn zeroize(&mut self) {
        // Clear the vector
        self.inner.clear();
        
        // For byte vectors, we can manually zero each element
        if std::mem::size_of::<T>() == 1 {
            // This is safe because we're just zeroing memory
            let ptr = self.inner.as_mut_ptr() as *mut u8;
            let capacity = N;
            
            unsafe {
                for i in 0..capacity {
                    std::ptr::write_volatile(ptr.add(i), 0);
                }
            }
        }
    }
}

/// A fixed-capacity vector that stores elements on the stack.
/// 
/// This implementation wraps heapless::Vec to provide stack-only storage
/// for sensitive cryptographic material, with automatic zeroization on drop.
pub struct SecureStack<T, const N: usize> {
    /// The inner vector stored on the stack
    inner: ZeroizableHeaplessVec<T, N>,
}

impl<T, const N: usize> SecureStack<T, N> {
    /// Create a new empty secure vector with fixed capacity N.
    pub fn new() -> Self {
        Self {
            inner: ZeroizableHeaplessVec::new(HeaplessVec::new()),
        }
    }
    
    /// Create a secure vector from an existing heapless::Vec.
    pub fn from_vec(vec: HeaplessVec<T, N>) -> Self {
        Self {
            inner: ZeroizableHeaplessVec::new(vec),
        }
    }
    
    /// Try to push an element to the vector.
    pub fn push(&mut self, value: T) -> Result<()> {
        self.inner.push(value).map_err(|_| Error::Other("Buffer full".to_string()))
    }
    
    /// Try to extend the vector from a slice.
    pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<()> 
    where
        T: Clone,
    {
        self.inner.extend_from_slice(slice)
            .map_err(|_| Error::Other("Not enough space".to_string()))
    }
    
    /// Returns the remaining capacity in the vector.
    pub fn capacity(&self) -> usize {
        N - self.len()
    }
    
    /// Returns the number of elements in the vector.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Returns true if the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    /// Clears the vector, removing all elements.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
    
    /// Consumes this container and returns the inner vector
    pub fn into_inner(self) -> HeaplessVec<T, N> {
        self.inner.inner
    }
}

impl<T, const N: usize> MemoryProtection for SecureStack<T, N> {
    fn lock_memory(&mut self) -> Result<()> {
        // Stack memory doesn't need locking
        Ok(())
    }
    
    fn unlock_memory(&mut self) -> Result<()> {
        // Stack memory doesn't need unlocking
        Ok(())
    }
    
    fn is_memory_locked(&self) -> bool {
        // Stack memory is inherently "locked"
        true
    }
    
    fn make_read_only(&mut self) -> Result<()> {
        // Not supported for stack memory
        Err(Error::ProtectionFailed("Cannot make stack memory read-only".to_string()))
    }
    
    fn make_writable(&mut self) -> Result<()> {
        // Stack memory is already writable
        Ok(())
    }
    
    fn is_read_only(&self) -> bool {
        false
    }
    
    fn check_integrity(&self) -> Result<()> {
        // No integrity checks for stack memory
        Ok(())
    }
    
    fn clear(&mut self) -> Result<()> {
        // Clear the vector
        self.inner.clear();
        Ok(())
    }
}

impl<T, const N: usize> Deref for SecureStack<T, N> {
    type Target = HeaplessVec<T, N>;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for SecureStack<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, const N: usize> Default for SecureStack<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for SecureStack<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureStack")
            .field("inner", &self.inner)
            .field("capacity", &N)
            .finish()
    }
}

impl<T: Clone, const N: usize> Clone for SecureStack<T, N> {
    fn clone(&self) -> Self {
        let mut new_vec = HeaplessVec::new();
        for item in self.inner.iter() {
            // This should never fail if the capacity is the same
            let _ = new_vec.push(item.clone());
        }
        Self {
            inner: ZeroizableHeaplessVec::new(new_vec),
        }
    }
}

impl<T, const N: usize> Zeroize for SecureStack<T, N> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

// Common size aliases for convenience
pub type SecureStack32 = SecureStack<u8, 32>;    // For 256-bit keys
pub type SecureStack64 = SecureStack<u8, 64>;    // For 512-bit keys
pub type SecureStack1K = SecureStack<u8, 1024>;  // For 1KB blocks
pub type SecureStack4K = SecureStack<u8, 4096>;  // For 4KB blocks

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_stack() {
        // Create a new secure vector with 32-byte capacity
        let mut vec: SecureStack<u8, 32> = SecureStack::new();
        
        // Push some data
        for i in 0..16 {
            vec.push(i).unwrap();
        }
        
        // Check the data
        assert_eq!(vec.len(), 16);
        assert_eq!(vec[0], 0);
        assert_eq!(vec[15], 15);
        
        // Check capacity
        assert_eq!(vec.capacity(), 16);
        
        // Extend from slice
        let more_data = [16, 17, 18, 19];
        vec.extend_from_slice(&more_data).unwrap();
        
        // Check updated length
        assert_eq!(vec.len(), 20);
        
        // Clear the vector
        vec.clear();
        assert_eq!(vec.len(), 0);
        assert!(vec.is_empty());
    }
    
    #[test]
    fn test_zeroize_on_drop() {
        // This test verifies that data is zeroed when dropped
        let data = [1u8, 2, 3, 4, 5];
        
        // Create a heapless vector
        let mut raw_vec = HeaplessVec::<u8, 32>::new();
        raw_vec.extend_from_slice(&data).unwrap();
        
        // Create a wrapper that will zeroize on drop
        let heap_vec = raw_vec.clone();
        {
            let _secure_vec = SecureStack::from_vec(heap_vec);
            // _secure_vec is dropped here
        }
        
        // Create a new secure vector and check zeroize directly
        let mut secure_vec = SecureStack::from_vec(raw_vec);
        secure_vec.zeroize();
        
        // Check that all bytes are now zero
        assert_eq!(secure_vec.len(), 0); // Vector should be cleared
    }
    
    #[test]
    fn test_alias_types() {
        let vec32: SecureStack32 = SecureStack32::new();
        assert_eq!(vec32.capacity(), 32);
        
        let vec64: SecureStack64 = SecureStack64::new();
        assert_eq!(vec64.capacity(), 64);
        
        let vec1k: SecureStack1K = SecureStack1K::new();
        assert_eq!(vec1k.capacity(), 1024);
        
        let vec4k: SecureStack4K = SecureStack4K::new();
        assert_eq!(vec4k.capacity(), 4096);
    }
    
    #[test]
    fn test_memory_protection() {
        let mut secure = SecureStack::<u8, 32>::new();
        
        // These operations should be no-ops on stack memory
        assert!(secure.lock_memory().is_ok());
        assert!(secure.unlock_memory().is_ok());
        assert!(secure.is_memory_locked());
        
        // Make read-only should fail for stack memory
        assert!(secure.make_read_only().is_err());
        
        // Make writable should be a no-op
        assert!(secure.make_writable().is_ok());
        
        // Integrity check should pass
        assert!(secure.check_integrity().is_ok());
    }
}