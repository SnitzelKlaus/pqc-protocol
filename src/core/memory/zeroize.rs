/*!
Secure memory zeroization utilities for the PQC protocol.

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

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        secure_zero_memory(self);
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
    
    // Use the memory to prevent dead store elimination
    let mut sum = 0u8;
    for &byte in memory.iter() {
        sum = sum.wrapping_add(byte);
    }
    
    // Force the compiler to use the sum
    if sum != 0 {
        unsafe {
            ptr::write_volatile(&mut memory[0], sum);
            ptr::write_volatile(&mut memory[0], 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zeroize_trait() {
        let mut data = [42u8; 64];
        
        // Zeroize the memory
        data.zeroize();
        
        // Check that all bytes are zero
        for byte in &data {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_zero_memory() {
        let mut data = [0xFFu8; 128];
        
        // Zeroize the memory
        secure_zero_memory(&mut data);
        
        // Check that all bytes are zero
        for byte in &data {
            assert_eq!(*byte, 0);
        }
    }
}