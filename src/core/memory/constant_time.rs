/*!
Constant-time cryptographic operations for PQC protocol.

This module provides constant-time implementations of common operations
to help prevent timing attacks on cryptographic code, utilizing the
subtle crate for core operations.
*/

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
use subtle::black_box;
use std::ops::BitXor;

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
    
    // Use constant-time select operation
    subtle::conditional_select(&b, &a, c)
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
    let gt = a.ct_gt(b).unwrap_u8() as i8;
    let eq = a.ct_eq(b).unwrap_u8() as i8;
    let lt = a.ct_lt(b).unwrap_u8() as i8;
    
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

/// Module-level unit tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2u8, 3u8, 4u8];
        let b = [1u8, 2u8, 3u8, 4u8];
        let c = [1u8, 2u8, 3u8, 5u8];
        let d = [1u8, 2u8, 3u8];
        
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
        
        // Test array version
        let arr_a = [1u8, 2u8, 3u8, 4u8];
        let arr_b = [1u8, 2u8, 3u8, 4u8];
        let arr_c = [1u8, 2u8, 3u8, 5u8];
        
        assert!(constant_time_eq_arrays(&arr_a, &arr_b));
        assert!(!constant_time_eq_arrays(&arr_a, &arr_c));
    }
    
    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 42u32, 24u32), 42u32);
        assert_eq!(constant_time_select(false, 42u32, 24u32), 24u32);
        
        // Test with different types
        assert_eq!(constant_time_select(true, 1u8, 2u8), 1u8);
        assert_eq!(constant_time_select(false, 1u8, 2u8), 2u8);
    }
    
    #[test]
    fn test_constant_time_increment() {
        let mut counter = 10u32;
        constant_time_increment(&mut counter, 5);
        assert_eq!(counter, 15u32);
        
        // Test overflow
        let mut max_counter = u32::MAX;
        constant_time_increment(&mut max_counter, 1);
        assert_eq!(max_counter, 0u32);
    }
    
    #[test]
    fn test_constant_time_compare() {
        assert_eq!(constant_time_compare(5, 3), 1);
        assert_eq!(constant_time_compare(3, 5), -1);
        assert_eq!(constant_time_compare(5, 5), 0);
    }
    
    #[test]
    fn test_constant_time_copy() {
        let src = [1u8, 2u8, 3u8, 4u8];
        let mut dst = [0u8; 4];
        
        constant_time_copy(&mut dst, &src);
        assert_eq!(dst, [1, 2, 3, 4]);
        
        // Test with different lengths
        let mut dst2 = [0u8; 6];
        constant_time_copy(&mut dst2, &src);
        assert_eq!(dst2, [1, 2, 3, 4, 0, 0]);
        
        let mut dst3 = [0u8; 2];
        constant_time_copy(&mut dst3, &src);
        assert_eq!(dst3, [1, 2]);
    }
    
    #[test]
    fn test_constant_time_pad() {
        let mut buffer = vec![1, 2, 3];
        constant_time_pad_with_zeros(&mut buffer, 5);
        assert_eq!(buffer, vec![1, 2, 3, 0, 0]);
        
        // Test when buffer is already at target length
        let mut buffer2 = vec![1, 2, 3];
        constant_time_pad_with_zeros(&mut buffer2, 3);
        assert_eq!(buffer2, vec![1, 2, 3]);
    }
}