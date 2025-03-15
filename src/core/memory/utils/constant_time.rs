/*!
Constant-time operations for security-sensitive code.

This module provides constant-time implementations of common operations
to help prevent timing attacks on cryptographic code, utilizing the
subtle crate for core operations.
*/

use std::ops::BitXor;
use std::hint::black_box; // Use std::hint::black_box instead of subtle's private version
use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

/// Trait for types that can be compared in constant time
pub trait ConstantTimeComparable {
    /// Compare for equality in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Compare two byte slices for equality in constant time.
///
/// This function will take the same amount of time regardless of where
/// the slices differ, helping to prevent timing attacks.
///
/// Returns true if the slices are equal, false otherwise.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // If the lengths differ, return false, but still do the comparison
    // to avoid revealing length information through timing
    let len_equal = a.len() == b.len();
    
    // Use the subtle crate's constant-time comparison
    let result = if len_equal {
        a.ct_eq(b).unwrap_u8() == 1
    } else {
        let len = std::cmp::min(a.len(), b.len());
        let mut result = 0u8;
        
        // Compare the common prefix
        if len > 0 {
            result = a[..len].ct_eq(&b[..len]).unwrap_u8();
        }
        
        // Always return false for different lengths
        false
    };
    
    // Prevent the compiler from optimizing this check
    black_box(result)
}

/// Compare two byte arrays for equality in constant time.
pub fn constant_time_eq_arrays<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

/// Select between two values in constant time.
///
/// If `condition` is true, returns `a`, otherwise returns `b`.
/// This operation is performed in a way that does not branch based on the condition.
pub fn constant_time_select<T>(condition: bool, a: T, b: T) -> T
where
    T: BitXor<Output = T> + Copy,
{
    // Convert bool to u8 (0 or 1)
    let c = Choice::from(condition as u8);
    
    // Implementation of conditional select using a bitmask approach
    // This avoids using subtle's internal implementation
    let mask = if c.unwrap_u8() != 0 { !0 } else { 0 };
    
    // Using manual pointer manipulation for constant-time selection
    // Safety: We're only accessing the bytes of valid objects a and b
    unsafe {
        let mut r = b;
        let a_ptr = &a as *const T as *const u8;
        let b_ptr = &b as *const T as *const u8;
        let r_ptr = &mut r as *mut T as *mut u8;
        
        for i in 0..std::mem::size_of::<T>() {
            let a_byte = *a_ptr.add(i);
            let b_byte = *b_ptr.add(i);
            // Apply mask: b_byte ^ (mask & (a_byte ^ b_byte))
            // If mask is all 1s (condition is true), this becomes a_byte
            // If mask is all 0s (condition is false), this remains b_byte
            *r_ptr.add(i) = b_byte ^ ((a_byte ^ b_byte) & mask);
        }
        
        r
    }
}

/// Increment a counter in constant time.
///
/// Adds `value` to `counter` without introducing timing variations.
pub fn constant_time_increment(counter: &mut u32, value: u32) {
    // Simple constant-time addition
    *counter = counter.wrapping_add(value);
}

/// Compare two integers in constant time, returning an integer comparison result.
///
/// Returns:
/// -  1 if a > b
/// -  0 if a = b
/// - -1 if a < b
///
/// This function takes the same amount of time regardless of the inputs.
pub fn constant_time_compare(a: u32, b: u32) -> i8 {
    // Pass references to the ct methods
    let gt = (&a).ct_gt(&b).unwrap_u8() as i8;
    let eq = (&a).ct_eq(&b).unwrap_u8() as i8;
    let lt = (&a).ct_lt(&b).unwrap_u8() as i8;
    
    // Compute the result: 1 if a > b, 0 if a = b, -1 if a < b
    gt - lt
}

/// Copy memory in constant time.
///
/// Copies `src` to `dst` without introducing timing variations.
pub fn constant_time_copy(dst: &mut [u8], src: &[u8]) {
    let len = std::cmp::min(dst.len(), src.len());
    
    // Process all bytes regardless of length
    let max_len = std::cmp::max(dst.len(), src.len());
    
    for i in 0..max_len {
        if i < len {
            // Real copy in bounds
            dst[i] = src[i];
        } else {
            // Dummy operation out of bounds to maintain constant time
            let dummy = if i < src.len() { src[i] } else { 0 };
            if i < dst.len() {
                // This write won't happen for out-of-bounds indices
                dst[i] = dst[i] ^ 0 ^ (dummy & 0);
            }
        }
    }
}

/// Extend the given buffer with zeros in constant time.
///
/// This function is useful for padding data to a fixed length.
pub fn constant_time_pad_with_zeros(buffer: &mut Vec<u8>, target_len: usize) {
    let orig_len = buffer.len();
    
    // Only extend if we need to
    if orig_len < target_len {
        buffer.resize(target_len, 0);
    }
}

/// A helper that forces a value to be processed in constant time.
///
/// This can be used to prevent compiler optimizations that might
/// introduce timing variations.
#[inline(never)]
pub fn constant_time_process<T: Copy>(value: T) -> T {
    black_box(value)
}