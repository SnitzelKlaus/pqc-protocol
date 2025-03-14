/*!
Zero-on-drop wrapper for secure memory in the PQC protocol.

This module provides a wrapper type that automatically zeroizes memory
when it goes out of scope, ensuring that sensitive cryptographic material
is not left in memory.
*/

use crate::core::memory::zeroize::Zeroize;
use std::fmt;
use std::ops::{Deref, DerefMut};

/// A wrapper that automatically zeroizes its contents when dropped.
///
/// This ensures that sensitive cryptographic material (like keys, seeds, etc.)
/// is properly erased from memory when it's no longer needed, reducing the
/// risk of key material being exposed in a memory dump.
pub struct ZeroizeOnDrop<T: Zeroize> {
    /// Inner value that will be zeroized on drop
    inner: T,
}

impl<T: Zeroize> ZeroizeOnDrop<T> {
    /// Create a new ZeroizeOnDrop wrapper around a value.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Consume the wrapper and return the inner value without zeroizing.
    ///
    /// # Security Warning
    ///
    /// This method is intended for cases where you need to transfer ownership
    /// of the sensitive data to another component or function. Be careful using
    /// this method as it bypasses the automatic zeroization.
    pub fn into_inner(self) -> T {
        let inner = std::mem::ManuallyDrop::new(self);
        // Safety: we're transferring ownership without running the destructor
        unsafe { std::ptr::read(&inner.inner) }
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
        self.inner.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for ZeroizeOnDrop<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl<T: Zeroize + fmt::Debug> fmt::Debug for ZeroizeOnDrop<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizeOnDrop({:?})", self.inner)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_on_drop() {
        // Create a wrapper around a vector that we'll check is zeroized
        let mut test_vec = vec![1u8, 2u8, 3u8, 4u8];
        
        {
            // Create a ZeroizeOnDrop that borrows test_vec
            let mut wrapper = ZeroizeOnDrop::new(&mut test_vec);
            
            // We can still access the vector through the wrapper
            assert_eq!(*wrapper, vec![1u8, 2u8, 3u8, 4u8]);
            
            // We can modify the vector through the wrapper
            wrapper[0] = 0;
            assert_eq!(*wrapper, vec![0u8, 2u8, 3u8, 4u8]);
        }
        // wrapper is dropped here, should zeroize test_vec
        
        // Check that test_vec was indeed zeroized
        assert_eq!(test_vec, vec![0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_into_inner() {
        let data = vec![1u8, 2u8, 3u8];
        let wrapper = ZeroizeOnDrop::new(data.clone());
        
        // Extract the inner value
        let extracted = wrapper.into_inner();
        
        // Verify that the data wasn't zeroized
        assert_eq!(extracted, data);
    }
}