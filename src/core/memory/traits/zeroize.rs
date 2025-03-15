/*!
Secure memory zeroization traits and utilities.

This module provides traits and functions for securely zeroing memory
to prevent sensitive data leakage.
*/

use std::ptr;
use std::sync::atomic::Ordering;

/// Trait for securely zeroing memory for sensitive data types
pub trait Zeroize {
    /// Securely zero this object's memory
    fn zeroize(&mut self);
}

/// Implementation of Zeroize for byte slices
impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        secure_zero_memory(self);
    }
}

/// Implementation of Zeroize for byte arrays of any size
impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        secure_zero_memory(self.as_mut_slice());
    }
}

/// Implementation of Zeroize for Vec<u8>
impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        secure_zero_memory(self.as_mut_slice());
    }
}

/// Implementation of Zeroize for String
impl Zeroize for String {
    fn zeroize(&mut self) {
        // Get mutable reference to the string's bytes
        let bytes = unsafe { 
            self.as_bytes_mut() 
        };
        
        // Zero out all bytes in the string
        secure_zero_memory(bytes);
        
        // Clear the string
        self.clear();
    }
}

/// Implementation of Zeroize for Option<T> where T: Zeroize
impl<T: Zeroize> Zeroize for Option<T> {
    fn zeroize(&mut self) {
        if let Some(value) = self.as_mut() {
            value.zeroize();
        }
    }
}

/// Implementation of Zeroize for &mut T where T: Zeroize
impl<T: Zeroize> Zeroize for &mut T {
    fn zeroize(&mut self) {
        (*self).zeroize();
    }
}

/// Helper to securely zero memory - explicitly marked as not inlineable
/// to prevent compiler optimizations
#[inline(never)]
pub fn secure_zero_memory(memory: &mut [u8]) {
    // Use volatile writes to ensure the compiler doesn't optimize away
    for byte in memory.iter_mut() {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    
    // Add a memory fence to prevent reordering
    std::sync::atomic::fence(Ordering::SeqCst);
    
    // This forces use of the zeroed memory to ensure the compiler doesn't
    // remove it as a dead store. This works because:
    // 1. The compiler doesn't know the return value of black_box
    // 2. The compiler must assume it affects memory in arbitrary ways
    use std::hint::black_box;
    black_box(memory);
}

/// Utility function to erase sensitive data
/// This just calls zeroize but makes the intent clearer
#[inline]
pub fn erase<T: Zeroize>(data: &mut T) {
    data.zeroize();
}