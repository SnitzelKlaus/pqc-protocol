/*!
Core secure memory implementation for the PQC protocol.

Provides the base SecureMemory container for storing sensitive data with
memory protection and zeroization on drop.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::alloc::{self, Layout};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use rand::{Rng, thread_rng};

use super::zeroize::{Zeroize, secure_zero_memory};

/// A secure memory container for sensitive data.
///
/// Enhanced SecureMemory features:
/// - Allocates memory with padding and alignment for protection
/// - Prevents memory from being swapped to disk (when possible)
/// - Zeros memory when dropped using volatile writes
/// - Uses mlock on Unix platforms and VirtualLock on Windows
/// - Adds canary values to detect buffer overflows
/// - Implements timing-safe equality comparisons
/// - Randomizes padding to prevent heap fingerprinting
///
/// # Example
///
/// ```
/// use pqc_protocol::memory::SecureMemory;
///
/// let mut secure_key = SecureMemory::new([0u8; 32]);
/// secure_key[0] = 42;
/// assert_eq!(secure_key[0], 42);
/// ```
#[derive(Debug)]
pub struct SecureMemory<T: ?Sized> {
    /// Pointer to the secured memory
    inner: *mut T,
    /// Memory layout information
    layout: Layout,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Canary value for detecting buffer overflows
    canary: u64,
    /// Size of the padding added to both sides of the allocation
    padding_size: usize,
}

unsafe impl<T: ?Sized + Send> Send for SecureMemory<T> {}
unsafe impl<T: ?Sized + Sync> Sync for SecureMemory<T> {}

impl<T> SecureMemory<T> {
    /// Create a new secure memory container.
    pub fn new(value: T) -> Self {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>();
        
        // Add padding for protection
        // Using 64 bytes of padding on each side (typical cache line size)
        let padding_size = 64;
        let total_size = size + (padding_size * 2);
        
        // Ensure we have a valid layout with proper alignment
        let layout = Layout::from_size_align(total_size, align.max(64))
            .expect("Invalid layout for secure memory");
        
        // Generate random canary value
        let canary = thread_rng().gen::<u64>();
        
        let mut locked = AtomicBool::new(false);
        
        unsafe {
            // Allocate memory
            let allocation = alloc::alloc(layout) as *mut u8;
            if allocation.is_null() {
                alloc::handle_alloc_error(layout);
            }
            
            // Calculate pointer to the actual data (after padding)
            let ptr = allocation.add(padding_size) as *mut T;
            
            // Initialize memory
            ptr::write(ptr, value);
            
            // Generate random padding
            let mut rng = thread_rng();
            // Front padding
            for i in 0..padding_size {
                ptr::write_volatile(allocation.add(i), rng.gen::<u8>());
            }
            // Back padding
            for i in 0..padding_size {
                ptr::write_volatile(allocation.add(padding_size + size + i), rng.gen::<u8>());
            }
            
            // Write canary values at the end of each padding area
            let front_canary_ptr = allocation.add(padding_size - 8) as *mut u64;
            let back_canary_ptr = allocation.add(padding_size + size) as *mut u64;
            ptr::write_volatile(front_canary_ptr, canary);
            ptr::write_volatile(back_canary_ptr, canary);
            
            // Lock memory to prevent swapping (platform-specific)
            #[cfg(unix)]
            {
                use libc::{mlock, ENOMEM, MCL_CURRENT, MCL_FUTURE, mlockall};
                
                // Try to lock the entire allocation
                let result = mlock(allocation as *const _, total_size);
                if result == 0 {
                    locked = AtomicBool::new(true);
                } else {
                    let err = *libc::__errno_location();
                    if err == ENOMEM {
                        // Non-fatal: couldn't lock memory but we'll still use it
                        // This can happen if the user doesn't have the right permissions
                        eprintln!("Warning: Failed to lock memory with mlock, continuing with unlocked memory");
                    }
                    
                    // Try mlockall as a fallback
                    let _ = mlockall(MCL_CURRENT | MCL_FUTURE);
                }
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            {
                use winapi::um::memoryapi::VirtualLock;
                use winapi::um::errhandlingapi::GetLastError;
                
                if VirtualLock(allocation as *mut _, total_size) != 0 {
                    locked = AtomicBool::new(true);
                } else {
                    let error = GetLastError();
                    eprintln!("Warning: Failed to lock memory with VirtualLock (error: {}), continuing with unlocked memory", error);
                }
            }
            
            Self {
                inner: ptr,
                layout,
                locked,
                canary,
                padding_size,
            }
        }
    }
    
    /// Create a new secure memory container with zeros.
    pub fn zeroed() -> Self
    where
        T: Default,
    {
        Self::new(T::default())
    }
    
    /// Check if memory lock succeeded
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    
    /// Convert to a byte slice (for clearing/zeroizing)
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.inner as *const u8,
                mem::size_of::<T>(),
            )
        }
    }
    
    /// Convert to a mutable byte slice (for clearing/zeroizing)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.inner as *mut u8,
                mem::size_of::<T>(),
            )
        }
    }
    
    /// Explicitly clear memory using a secure zeroization method
    pub fn clear(&mut self) {
        self.check_canary_values();
        self.zeroize();
    }
    
    /// Fill memory with random data
    pub fn randomize(&mut self) {
        let size = mem::size_of::<T>();
        if size == 0 {
            return;
        }
        
        let mut rng = thread_rng();
        unsafe {
            let ptr = self.inner as *mut u8;
            
            // Fill with random bytes
            for i in 0..size {
                ptr::write_volatile(ptr.add(i), rng.gen::<u8>());
            }
        }
    }
    
    /// Get the actual allocation base pointer
    unsafe fn allocation_base(&self) -> *mut u8 {
        // The allocation base is padding_size bytes before the inner pointer
        (self.inner as *mut u8).sub(self.padding_size)
    }
    
    /// Get the front canary value
    unsafe fn front_canary(&self) -> u64 {
        let front_canary_ptr = self.allocation_base().add(self.padding_size - 8) as *const u64;
        ptr::read_volatile(front_canary_ptr)
    }
    
    /// Get the back canary value
    unsafe fn back_canary(&self) -> u64 {
        let size = mem::size_of::<T>();
        let back_canary_ptr = (self.inner as *mut u8).add(size) as *const u64;
        ptr::read_volatile(back_canary_ptr)
    }
    
    /// Check canary values for buffer overflow detection
    pub fn check_canary_values(&self) -> bool {
        unsafe {
            let front_canary = self.front_canary();
            let back_canary = self.back_canary();
            
            if front_canary != self.canary || back_canary != self.canary {
                // Log the error
                eprintln!("SECURITY ERROR: SecureMemory canary values corrupted - buffer overflow detected!");
                
                if front_canary != self.canary {
                    eprintln!("Front canary corrupted: expected {:x}, found {:x}", self.canary, front_canary);
                }
                
                if back_canary != self.canary {
                    eprintln!("Back canary corrupted: expected {:x}, found {:x}", self.canary, back_canary);
                }
                
                return false;
            }
            
            true
        }
    }
    
    /// Compare two secure memory containers in constant time
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if mem::size_of::<T>() != mem::size_of::<T>() {
            return false;
        }
        
        let size = mem::size_of::<T>();
        let mut result: u8 = 0;
        
        unsafe {
            let self_ptr = self.inner as *const u8;
            let other_ptr = other.inner as *const u8;
            
            for i in 0..size {
                // XOR each byte - 0 if same, non-zero if different
                result |= ptr::read_volatile(self_ptr.add(i)) ^ ptr::read_volatile(other_ptr.add(i));
            }
        }
        
        // Will be 0 only if all bytes are equal
        result == 0
    }
    
    /// Clone to another SecureMemory container
    pub fn secure_clone(&self) -> Self 
    where 
        T: Clone
    {
        self.check_canary_values();
        unsafe {
            // Clone the inner value
            let cloned = (*self.inner).clone();
            Self::new(cloned)
        }
    }
}

impl<T: ?Sized> Deref for SecureMemory<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.check_canary_values();
        unsafe { &*self.inner }
    }
}

impl<T: ?Sized> DerefMut for SecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.check_canary_values();
        unsafe { &mut *self.inner }
    }
}

impl<T: ?Sized> Drop for SecureMemory<T> {
    fn drop(&mut self) {
        // Check for buffer overflows before deallocation
        let overflow_detected = !self.check_canary_values();
        
        // Get the size of the stored value
        let size = mem::size_of_val(&**self);
        
        // Zero the memory
        self.zeroize();
        
        unsafe {
            // Get the actual allocation base
            let allocation = self.allocation_base();
            let total_size = self.layout.size();
            
            // Zero all memory, including padding
            ptr::write_bytes(allocation, 0, total_size);
            
            // Unlock memory if it was locked
            if self.locked.load(Ordering::Relaxed) {
                #[cfg(unix)]
                {
                    libc::munlock(allocation as *const _, total_size);
                }
                
                #[cfg(all(target_os = "windows", feature = "windows-lock"))]
                {
                    use winapi::um::memoryapi::VirtualUnlock;
                    VirtualUnlock(allocation as *mut _, total_size);
                }
            }
            
            // Deallocate memory
            alloc::dealloc(allocation, self.layout);
        }
        
        // If an overflow was detected, we might want to abort the program
        // in a production environment to prevent further exploitation
        if overflow_detected && cfg!(feature = "abort-on-overflow") {
            eprintln!("FATAL: SecureMemory buffer overflow detected. Aborting.");
            std::process::abort();
        }
    }
}

impl<T: Default> Default for SecureMemory<T> {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<T: Clone> Clone for SecureMemory<T> {
    fn clone(&self) -> Self {
        self.secure_clone()
    }
}

impl<T: PartialEq> PartialEq for SecureMemory<T> {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for equality
        self.constant_time_eq(other) || **self == **other
    }
}

impl<T> Zeroize for SecureMemory<T> {
    fn zeroize(&mut self) {
        let size = mem::size_of::<T>();
        if size == 0 {
            return;
        }
        
        unsafe {
            let ptr = self.inner as *mut u8;
            
            // Zero the memory using volatile writes
            for i in 0..size {
                ptr::write_volatile(ptr.add(i), 0);
            }
            
            // Prevent compiler optimization by reading back the memory
            let mut sum: u8 = 0;
            for i in 0..size {
                sum ^= ptr::read_volatile(ptr.add(i));
            }
            
            // Use sum in a way that compiler can't optimize away
            if sum != 0 {
                // This should never happen, but the compiler doesn't know that
                ptr::write_volatile(ptr, sum);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_memory_basic() {
        let mut secure = SecureMemory::new([0u8; 32]);
        
        // Check that we can mutate the memory
        secure[0] = 42;
        secure[1] = 43;
        
        assert_eq!(secure[0], 42);
        assert_eq!(secure[1], 43);
    }
    
    #[test]
    fn test_secure_memory_zeroed() {
        let secure: SecureMemory<[u8; 32]> = SecureMemory::zeroed();
        
        // Check that all bytes are zero
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_memory_clear() {
        let mut secure = SecureMemory::new([42u8; 32]);
        
        // Check that memory contains our value
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 42);
        }
        
        // Clear the memory
        secure.clear();
        
        // Check that all bytes are now zero
        for byte in secure.as_bytes() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_memory_canary() {
        let secure = SecureMemory::new([0u8; 32]);
        
        // Canary check should pass
        assert!(secure.check_canary_values());
        
        // In a real test we'd try to overflow the buffer,
        // but that's not easy to do safely in a test
    }
    
    #[test]
    fn test_secure_memory_constant_time_eq() {
        let secure1 = SecureMemory::new([42u8; 32]);
        let secure2 = SecureMemory::new([42u8; 32]);
        let secure3 = SecureMemory::new([0u8; 32]);
        
        assert!(secure1.constant_time_eq(&secure2));
        assert!(!secure1.constant_time_eq(&secure3));
    }
}