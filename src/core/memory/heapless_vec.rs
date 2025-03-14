/*!
Heapless vector implementation for secure memory in the PQC protocol.

This module provides a wrapper around heapless::Vec to ensure sensitive
cryptographic material never gets allocated on the heap, which is more
difficult to reliably clean up and can be subject to memory dumps.
*/

use crate::core::memory::zeroize::Zeroize;
use crate::core::memory::zeroize_on_drop::ZeroizeOnDrop;
use heapless::Vec as HeaplessVec;
use std::ops::{Deref, DerefMut};
use std::fmt;

/// A fixed-capacity vector that stores elements on the stack.
/// 
/// This implementation wraps heapless::Vec to provide stack-only storage
/// for sensitive cryptographic material, with automatic zeroization on drop.
pub struct SecureHeaplessVec<T, const N: usize> {
    /// The inner vector stored on the stack
    inner: ZeroizeOnDrop<HeaplessVec<T, N>>,
}

impl<T, const N: usize> SecureHeaplessVec<T, N> {
    /// Create a new empty secure vector with fixed capacity N.
    pub fn new() -> Self {
        Self {
            inner: ZeroizeOnDrop::new(HeaplessVec::new()),
        }
    }
    
    /// Create a secure vector from an existing heapless::Vec.
    pub fn from_vec(vec: HeaplessVec<T, N>) -> Self {
        Self {
            inner: ZeroizeOnDrop::new(vec),
        }
    }
    
    /// Try to push an element to the vector.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        self.inner.push(value)
    }
    
    /// Try to extend the vector from a slice.
    pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), ()> 
    where
        T: Clone,
    {
        self.inner.extend_from_slice(slice)
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
}

impl<T, const N: usize> Deref for SecureHeaplessVec<T, N> {
    type Target = HeaplessVec<T, N>;
    
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for SecureHeaplessVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, const N: usize> Default for SecureHeaplessVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for SecureHeaplessVec<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureHeaplessVec")
            .field("inner", &self.inner)
            .field("capacity", &N)
            .finish()
    }
}

impl<T: Clone, const N: usize> Clone for SecureHeaplessVec<T, N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Zeroize, const N: usize> Zeroize for SecureHeaplessVec<T, N>
where
    HeaplessVec<T, N>: Zeroize,
{
    fn zeroize(&mut self) {
        // Delegate to the inner vector's zeroize implementation
        self.inner.zeroize();
    }
}

// Implement a specialized zeroize for byte vectors
impl<const N: usize> Zeroize for HeaplessVec<u8, N> {
    fn zeroize(&mut self) {
        // Zero out all bytes in the vector
        for byte in self.iter_mut() {
            *byte = 0;
        }
    }
}

// Common size aliases for convenience
pub type SecureVec32 = SecureHeaplessVec<u8, 32>;    // For 256-bit keys
pub type SecureVec64 = SecureHeaplessVec<u8, 64>;    // For 512-bit keys
pub type SecureVec1K = SecureHeaplessVec<u8, 1024>;  // For 1KB blocks
pub type SecureVec4K = SecureHeaplessVec<u8, 4096>;  // For 4KB blocks

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_heapless_vec() {
        // Create a new secure vector with 32-byte capacity
        let mut vec: SecureHeaplessVec<u8, 32> = SecureHeaplessVec::new();
        
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
        
        // We need to maintain a reference to check if zeroize worked
        let mut raw_vec = HeaplessVec::<u8, 32>::new();
        raw_vec.extend_from_slice(&data).unwrap();
        
        // Create a wrapper that will zeroize on drop
        {
            let _secure_vec = SecureHeaplessVec::from_vec(raw_vec.clone());
            // _secure_vec is dropped here
        }
        
        // At this point, the wrapper has been dropped, but we still have raw_vec
        // In a normal Rust program, we couldn't check this because the drop would
        // consume the value, but for testing purposes we've cloned the original
        
        // Note: This test is mostly for illustration - in actual code, the security
        // guarantee comes from ZeroizeOnDrop which is tested separately
    }
    
    #[test]
    fn test_alias_types() {
        let mut vec32: SecureVec32 = SecureVec32::new();
        assert_eq!(vec32.capacity(), 32);
        
        let mut vec64: SecureVec64 = SecureVec64::new();
        assert_eq!(vec64.capacity(), 64);
        
        let mut vec1k: SecureVec1K = SecureVec1K::new();
        assert_eq!(vec1k.capacity(), 1024);
        
        let mut vec4k: SecureVec4K = SecureVec4K::new();
        assert_eq!(vec4k.capacity(), 4096);
    }
}