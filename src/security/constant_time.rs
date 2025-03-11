/*!
Constant-time cryptographic operations.

This module provides constant-time implementations of common operations
to help prevent timing attacks on cryptographic code.
*/

/// Compare two byte slices in constant time.
///
/// This function will take the same amount of time regardless of where
/// the slices differ, helping to prevent timing attacks.
///
/// Returns true if the slices are equal, false otherwise.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    // XOR all bytes and OR the result
    // This ensures we always go through all bytes even if we find a difference
    let mut result: u8 = 0;
    
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    // If all bytes are equal, result will be 0
    result == 0
}

/// Select between two values in constant time.
///
/// If `condition` is true, returns `a`, otherwise returns `b`.
/// This operation is performed in a way that does not branch based on the condition.
#[inline]
pub fn constant_time_select<T: Copy + Default>(condition: bool, a: T, b: T) -> T {
    // Convert bool to u8 (0 or 1)
    let mask = -(condition as i8) as u8;
    
    // Use size of T to construct masks
    let size = std::mem::size_of::<T>();
    let mut result_bytes = [0u8; 32]; // 32 bytes should be enough for most types
    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];
    
    // Safety: use only up to the size of T
    unsafe {
        std::ptr::copy_nonoverlapping(
            &a as *const T as *const u8,
            a_bytes.as_mut_ptr(),
            std::cmp::min(size, 32),
        );
        std::ptr::copy_nonoverlapping(
            &b as *const T as *const u8,
            b_bytes.as_mut_ptr(),
            std::cmp::min(size, 32),
        );
    }
    
    // Select bytes using the mask (constant-time)
    for i in 0..size {
        // For each byte: if mask is 0xFF (true), select a, else select b
        result_bytes[i] = (mask & a_bytes[i]) | (!mask & b_bytes[i]);
    }
    
    // Convert back to T
    let mut result = T::default();
    unsafe {
        std::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            &mut result as *mut T as *mut u8,
            std::cmp::min(size, 32),
        );
    }
    
    result
}

/// Increment a counter in constant time.
///
/// Adds `value` to `counter` without introducing timing variations.
/// This is useful for preventing side-channel attacks on counters
/// like sequence numbers.
#[inline]
pub fn constant_time_increment(counter: &mut u32, value: u32) {
    let old_value = *counter;
    *counter = old_value.wrapping_add(value);
}

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
    }
    
    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(true, 42u32, 24u32), 42u32);
        assert_eq!(constant_time_select(false, 42u32, 24u32), 24u32);
        
        assert_eq!(constant_time_select(true, 1.0f64, 2.0f64), 1.0f64);
        assert_eq!(constant_time_select(false, 1.0f64, 2.0f64), 2.0f64);
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
}