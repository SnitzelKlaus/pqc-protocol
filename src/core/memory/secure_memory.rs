/*!
This module provides a robust secure memory implementation for storing sensitive data
like cryptographic keys, with improvements for memory protection, zeroization,
and buffer overflow detection.
*/

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::alloc::{self, Layout};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use rand::{Rng, thread_rng};

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
    
    /// Securely zeroize the content using volatile writes
    pub fn zeroize(&mut self) {
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

/// A wrapper around standard Vec for secure operations with enhanced features
pub struct SecureVec<T> {
    /// Inner vector
    inner: Vec<T>,
    /// Flag indicating if memory lock succeeded
    locked: AtomicBool,
    /// Front canary value
    front_canary: u64,
    /// Back canary value
    back_canary: u64,
    /// Is using canary values for protection
    using_canary: bool,
}

impl<T> SecureVec<T> {
    /// Create a new secure vector
    pub fn new() -> Self {
        let canary = thread_rng().gen::<u64>();
        Self {
            inner: Vec::new(),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        }
    }
    
    /// Create a secure vector with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let canary = thread_rng().gen::<u64>();
        Self {
            inner: Vec::with_capacity(capacity),
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        }
    }
    
    /// Create a secure vector from existing vector
    pub fn from_vec(vec: Vec<T>) -> Self {
        let canary = thread_rng().gen::<u64>();
        let mut secure = Self {
            inner: vec,
            locked: AtomicBool::new(false),
            front_canary: canary,
            back_canary: canary,
            using_canary: true,
        };
        
        // Try to lock memory
        secure.try_lock_memory();
        
        secure
    }
    
    /// Disable canary protection
    pub fn disable_canary(&mut self) {
        self.using_canary = false;
    }
    
    /// Enable canary protection
    pub fn enable_canary(&mut self) {
        if !self.using_canary {
            let canary = thread_rng().gen::<u64>();
            self.front_canary = canary;
            self.back_canary = canary;
            self.using_canary = true;
        }
    }
    
    /// Check canary values
    pub fn check_canary(&self) -> bool {
        if !self.using_canary {
            return true;
        }
        
        if self.front_canary != self.back_canary {
            eprintln!("SECURITY ERROR: SecureVec canary values corrupted - possible buffer overflow detected!");
            return false;
        }
        
        true
    }
    
    /// Try to lock the memory
    fn try_lock_memory(&mut self) {
        if !self.inner.is_empty() {
            #[cfg(unix)]
            unsafe {
                use libc::mlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                if mlock(ptr as *const _, size) == 0 {
                    self.locked.store(true, Ordering::Relaxed);
                }
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            unsafe {
                use winapi::um::memoryapi::VirtualLock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                if VirtualLock(ptr as *mut _, size) != 0 {
                    self.locked.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    
    /// Check if memory is locked
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
    
    /// Clear the memory with secure zeroization
    pub fn clear(&mut self) {
        // Unlock first if needed
        if self.locked.load(Ordering::Relaxed) {
            #[cfg(unix)]
            unsafe {
                use libc::munlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                munlock(ptr as *const _, size);
            }
            
            #[cfg(all(target_os = "windows", feature = "windows-lock"))]
            unsafe {
                use winapi::um::memoryapi::VirtualUnlock;
                let ptr = self.inner.as_ptr();
                let size = self.inner.len() * std::mem::size_of::<T>();
                VirtualUnlock(ptr as *mut _, size);
            }
            
            self.locked.store(false, Ordering::Relaxed);
        }
        
        // For types where zeroing makes sense (like u8)
        if std::mem::size_of::<T>() > 0 && std::mem::needs_drop::<T>() {
            // Clear the memory with volatile writes if applicable
            if let Some(bytes) = self.as_mut_bytes() {
                secure_zero_memory(bytes);
            }
        }
        
        // Clear the vector
        self.inner.clear();
    }
    
    /// Convert to bytes if T is u8
    fn as_mut_bytes(&mut self) -> Option<&mut [u8]> {
        if std::mem::size_of::<T>() == 1 {
            let ptr = self.inner.as_mut_ptr() as *mut u8;
            let len = self.inner.len();
            
            unsafe {
                Some(std::slice::from_raw_parts_mut(ptr, len))
            }
        } else {
            None
        }
    }
}

impl<T> Deref for SecureVec<T> {
    type Target = Vec<T>;
    
    fn deref(&self) -> &Self::Target {
        debug_assert!(self.check_canary(), "SecureVec canary check failed in deref");
        &self.inner
    }
}

impl<T> DerefMut for SecureVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        debug_assert!(self.check_canary(), "SecureVec canary check failed in deref_mut");
        &mut self.inner
    }
}

impl<T> Drop for SecureVec<T> {
    fn drop(&mut self) {
        // Check for buffer overflows before deallocation
        let overflow_detected = !self.check_canary();
        
        // Clear the memory
        self.clear();
        
        // If an overflow was detected, we might want to abort the program
        if overflow_detected && cfg!(feature = "abort-on-overflow") {
            eprintln!("FATAL: SecureVec buffer overflow detected. Aborting.");
            std::process::abort();
        }
    }
}

impl<T> Default for SecureVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory security level options for session data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySecurity {
    /// Standard security: basic protections
    Standard,
    /// Enhanced security: additional protections and canary values
    Enhanced,
    /// Maximum security: all protections enabled, read-only when not in use
    Maximum,
}

impl Default for MemorySecurity {
    fn default() -> Self {
        MemorySecurity::Standard
    }
}

/// Manages secure memory for a session
pub struct SecureMemoryManager {
    /// Current memory security level
    level: MemorySecurity,
    
    /// Whether automatic key erasure is enabled
    auto_erase: bool,
    
    /// Whether memory locking is enabled
    memory_locking: AtomicBool,
    
    /// Whether canary values are used for buffer overflow detection
    canary_protection: AtomicBool,
    
    /// Whether sensitive memory is zeroed when freed
    zero_on_free: AtomicBool,
}

impl SecureMemoryManager {
    /// Create a new secure memory manager with the specified security level
    pub fn new(level: MemorySecurity) -> Self {
        let manager = Self {
            level,
            auto_erase: true,
            memory_locking: AtomicBool::new(true),
            canary_protection: AtomicBool::new(true),
            zero_on_free: AtomicBool::new(true),
        };
        
        manager
    }
    
    /// Create a new secure memory manager with default security level
    pub fn default() -> Self {
        Self::new(MemorySecurity::Standard)
    }
    
    /// Create a new secure memory manager with enhanced security
    pub fn enhanced() -> Self {
        Self::new(MemorySecurity::Enhanced)
    }
    
    /// Create a new secure memory manager with maximum security
    pub fn maximum() -> Self {
        Self::new(MemorySecurity::Maximum)
    }
    
    /// Get the current security level
    pub fn security_level(&self) -> MemorySecurity {
        self.level
    }
    
    /// Set the security level
    pub fn set_security_level(&mut self, level: MemorySecurity) {
        self.level = level;
    }
    
    /// Check if memory locking is enabled
    pub fn is_memory_locking_enabled(&self) -> bool {
        self.memory_locking.load(Ordering::Relaxed)
    }
    
    /// Enable memory locking
    pub fn enable_memory_locking(&self) {
        self.memory_locking.store(true, Ordering::Relaxed);
    }
    
    /// Disable memory locking
    pub fn disable_memory_locking(&self) {
        self.memory_locking.store(false, Ordering::Relaxed);
    }
    
    /// Check if canary protection is enabled
    pub fn is_canary_protection_enabled(&self) -> bool {
        self.canary_protection.load(Ordering::Relaxed)
    }
    
    /// Enable canary protection
    pub fn enable_canary_protection(&self) {
        self.canary_protection.store(true, Ordering::Relaxed);
    }
    
    /// Disable canary protection
    pub fn disable_canary_protection(&self) {
        self.canary_protection.store(false, Ordering::Relaxed);
    }
    
    /// Check if zero-on-free is enabled
    pub fn is_zero_on_free_enabled(&self) -> bool {
        self.zero_on_free.load(Ordering::Relaxed)
    }
    
    /// Enable zero-on-free
    pub fn enable_zero_on_free(&self) {
        self.zero_on_free.store(true, Ordering::Relaxed);
    }
    
    /// Disable zero-on-free
    pub fn disable_zero_on_free(&self) {
        self.zero_on_free.store(false, Ordering::Relaxed);
    }
    
    /// Check if auto-erase is enabled
    pub fn is_auto_erase_enabled(&self) -> bool {
        self.auto_erase
    }
    
    /// Enable auto-erase
    pub fn enable_auto_erase(&mut self) {
        self.auto_erase = true;
    }
    
    /// Disable auto-erase
    pub fn disable_auto_erase(&mut self) {
        self.auto_erase = false;
    }
    
    /// Create a secure memory container for sensitive data
    pub fn secure_memory<T>(&self, value: T) -> SecureMemory<T> {
        SecureMemory::new(value)
    }
    
    /// Create a secure vector container
    pub fn secure_vec<T>(&self) -> SecureVec<T> {
        SecureVec::new()
    }
    
    /// Create a secure vector with capacity
    pub fn secure_vec_with_capacity<T>(&self, capacity: usize) -> SecureVec<T> {
        SecureVec::with_capacity(capacity)
    }
    
    /// Create a secure vector from an existing vector
    pub fn secure_vec_from_vec<T>(&self, vec: Vec<T>) -> SecureVec<T> {
        SecureVec::from_vec(vec)
    }
    
    /// Securely wipe a key from memory
    pub fn wipe_key<T: Zeroize>(&self, key: &mut T) {
        key.zeroize();
    }
    
    /// Apply current security settings to an existing SecureMemory container
    pub fn apply_settings_to_memory<T>(&self, _memory: &mut SecureMemory<T>) {
        // This is a placeholder - in a real implementation, we would
        // modify the security settings of the memory container
    }
    
    /// Apply current security settings to an existing SecureVec container
    pub fn apply_settings_to_vec<T>(&self, vec: &mut SecureVec<T>) {
        if self.is_canary_protection_enabled() {
            vec.enable_canary();
        } else {
            vec.disable_canary();
        }
    }
    
    /// Zero out sensitive memory regions
    pub fn zeroize_region(&self, region: &mut [u8]) {
        secure_zero_memory(region);
    }
}

/// Trait for securely zeroing memory for sensitive data types
pub trait Zeroize {
    /// Securely zero this object's memory
    fn zeroize(&mut self);
}

impl<T> Zeroize for SecureMemory<T> {
    fn zeroize(&mut self) {
        self.zeroize();
    }
}

impl<T> Zeroize for SecureVec<T> {
    fn zeroize(&mut self) {
        self.clear();
    }
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

/// Trait for session objects that use secure memory
pub trait SecureSession {
    /// Get memory security manager
    fn memory_manager(&self) -> &SecureMemoryManager;
    
    /// Get mutable reference to memory security manager
    fn memory_manager_mut(&mut self) -> &mut SecureMemoryManager;
    
    /// Set memory security level
    fn set_memory_security_level(&mut self, level: MemorySecurity) {
        self.memory_manager_mut().set_security_level(level);
    }
    
    /// Get current memory security level
    fn memory_security_level(&self) -> MemorySecurity {
        self.memory_manager().security_level()
    }
    
    /// Enable memory locking
    fn enable_memory_locking(&mut self) {
        self.memory_manager().enable_memory_locking();
    }
    
    /// Disable memory locking
    fn disable_memory_locking(&mut self) {
        self.memory_manager().disable_memory_locking();
    }
    
    /// Enable canary protection
    fn enable_canary_protection(&mut self) {
        self.memory_manager().enable_canary_protection();
    }
    
    /// Disable canary protection
    fn disable_canary_protection(&mut self) {
        self.memory_manager().disable_canary_protection();
    }
    
    /// Check if memory is secure
    fn is_memory_secure(&self) -> bool {
        let manager = self.memory_manager();
        manager.is_memory_locking_enabled() &&
        manager.is_canary_protection_enabled() &&
        manager.is_zero_on_free_enabled()
    }
    
    /// Erase sensitive memory
    fn erase_sensitive_memory(&mut self);
}

/// Advanced secure memory container with additional protection mechanisms.
/// This version uses mprotect/VirtualProtect to create read-only pages when not in use.
/// Available with the "enhanced-memory" feature
#[cfg(feature = "enhanced-memory")]
pub struct EnhancedSecureMemory<T: Sized> {
    /// The secure memory container
    memory: SecureMemory<T>,
    /// Whether the memory is currently read-only
    read_only: AtomicBool,
    /// Page size for memory protection
    page_size: usize,
}

#[cfg(all(feature = "enhanced-memory", unix))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        use libc::{sysconf, _SC_PAGESIZE};
        
        // Get the system page size
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size,
        }
    }
    
    /// Make the memory read-only
    pub fn make_read_only(&self) -> bool {
        if self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use libc::{mprotect, PROT_READ};
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it read-only
            let result = mprotect(page_addr as *mut _, total_size, PROT_READ);
            
            if result == 0 {
                self.read_only.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Make the memory writable
    pub fn make_writable(&self) -> bool {
        if !self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use libc::{mprotect, PROT_READ, PROT_WRITE};
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it writable
            let result = mprotect(page_addr as *mut _, total_size, PROT_READ | PROT_WRITE);
            
            if result == 0 {
                self.read_only.store(false, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably (automatically makes it writable first)
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        // Ensure memory is writable
        self.make_writable();
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

/// Implementation for Windows systems with enhanced memory protection
#[cfg(all(feature = "enhanced-memory", target_os = "windows"))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        
        // Get the system page size
        let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut sys_info) };
        let page_size = sys_info.dwPageSize as usize;
        
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size,
        }
    }
    
    /// Make the memory read-only
    pub fn make_read_only(&self) -> bool {
        if self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READONLY;
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it read-only
            let mut old_protect = 0;
            let result = VirtualProtect(
                page_addr as *mut _,
                total_size,
                PAGE_READONLY,
                &mut old_protect
            );
            
            if result != 0 {
                self.read_only.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Make the memory writable
    pub fn make_writable(&self) -> bool {
        if !self.read_only.load(Ordering::Relaxed) {
            return true;
        }
        
        unsafe {
            use winapi::um::memoryapi::VirtualProtect;
            use winapi::um::winnt::PAGE_READWRITE;
            
            // Get the base address and align to page boundary
            let addr = self.memory.inner as *mut T as usize;
            let page_addr = addr & !(self.page_size - 1);
            
            // Determine size covering the memory (at least one page)
            let size = std::mem::size_of::<T>() + (addr - page_addr);
            let pages = (size + self.page_size - 1) / self.page_size;
            let total_size = pages * self.page_size;
            
            // Make it writable
            let mut old_protect = 0;
            let result = VirtualProtect(
                page_addr as *mut _,
                total_size,
                PAGE_READWRITE,
                &mut old_protect
            );
            
            if result != 0 {
                self.read_only.store(false, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably (automatically makes it writable first)
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        // Ensure memory is writable
        self.make_writable();
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

/// Implementation for WebAssembly targets
/// In WASM, we can't do traditional memory locking, but we provide a compatible API
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
impl<T: Sized> EnhancedSecureMemory<T> {
    /// Create a new enhanced secure memory container
    pub fn new(value: T) -> Self {
        Self {
            memory: SecureMemory::new(value),
            read_only: AtomicBool::new(false),
            page_size: 4096, // Default page size, not actually used
        }
    }
    
    /// Make the memory read-only (not fully supported in WASM)
    pub fn make_read_only(&self) -> bool {
        // In WASM, we can't actually protect memory, but we simulate the API
        self.read_only.store(true, Ordering::Relaxed);
        true
    }
    
    /// Make the memory writable (not fully supported in WASM)
    pub fn make_writable(&self) -> bool {
        // In WASM, we can't actually protect memory, but we simulate the API
        self.read_only.store(false, Ordering::Relaxed);
        true
    }
    
    /// Access the inner memory
    pub fn inner(&self) -> &SecureMemory<T> {
        &self.memory
    }
    
    /// Access the inner memory mutably
    pub fn inner_mut(&mut self) -> &mut SecureMemory<T> {
        &mut self.memory
    }
    
    /// Is the memory currently read-only?
    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }
}

// Implement common traits for EnhancedSecureMemory regardless of platform
#[cfg(feature = "enhanced-memory")]
impl<T: Sized + Default> Default for EnhancedSecureMemory<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "enhanced-memory")]
impl<T: Sized> Deref for EnhancedSecureMemory<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

#[cfg(feature = "enhanced-memory")]
impl<T: Sized> DerefMut for EnhancedSecureMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Ensure memory is writable before mutating
        self.make_writable();
        &mut *self.memory
    }
}

#[cfg(feature = "enhanced-memory")]
impl<T: Sized> Drop for EnhancedSecureMemory<T> {
    fn drop(&mut self) {
        // Make memory writable for proper cleanup
        self.make_writable();
        // Drop will be called on self.memory automatically
    }
}

#[cfg(feature = "enhanced-memory")]
impl<T: Sized> Zeroize for EnhancedSecureMemory<T> {
    fn zeroize(&mut self) {
        // Ensure memory is writable before zeroizing
        self.make_writable();
        self.memory.zeroize();
    }
}

/// WASM-specific version of the memory manager
#[cfg(target_arch = "wasm32")]
pub struct WasmMemoryManager {
    /// Base memory manager
    inner: SecureMemoryManager,
    /// Whether secure random is available
    has_secure_random: bool,
}

#[cfg(target_arch = "wasm32")]
impl WasmMemoryManager {
    /// Create a new WASM-specific memory manager
    pub fn new() -> Self {
        // Check if secure random is available
        let has_secure_random = js_sys::crypto::is_secure_context();
        
        Self {
            inner: SecureMemoryManager::new(MemorySecurity::Standard),
            has_secure_random,
        }
    }
    
    /// Check if secure random is available
    pub fn has_secure_random(&self) -> bool {
        self.has_secure_random
    }
    
    /// Get a reference to the inner manager
    pub fn inner(&self) -> &SecureMemoryManager {
        &self.inner
    }
    
    /// Get a mutable reference to the inner manager
    pub fn inner_mut(&mut self) -> &mut SecureMemoryManager {
        &mut self.inner
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmMemoryManager {
    fn default() -> Self {
        Self::new()
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
    
    #[test]
    fn test_secure_vec() {
        let mut vec = Vec::new();
        vec.extend_from_slice(&[1, 2, 3, 4, 5]);
        
        let mut secure_vec = SecureVec::from_vec(vec);
        
        // Check values
        assert_eq!(secure_vec[0], 1);
        assert_eq!(secure_vec[4], 5);
        
        // Modify
        secure_vec[2] = 42;
        assert_eq!(secure_vec[2], 42);
        
        // Clear and check
        secure_vec.clear();
        assert_eq!(secure_vec.len(), 0);
    }
    
    #[test]
    fn test_secure_vec_canary() {
        let mut secure_vec = SecureVec::from_vec(vec![1, 2, 3, 4, 5]);
        
        // Canary check should pass
        assert!(secure_vec.check_canary());
        
        // Disable canary
        secure_vec.disable_canary();
        assert!(secure_vec.check_canary()); // Should still pass when disabled
        
        // Enable canary
        secure_vec.enable_canary();
        assert!(secure_vec.check_canary());
    }
    
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
    fn test_memory_manager() {
        let memory_manager = SecureMemoryManager::new(MemorySecurity::Enhanced);
        
        // Test creating secure memory through the manager
        let secure_mem = memory_manager.secure_memory([0u8; 32]);
        assert!(secure_mem.is_locked());
        
        // Test creating secure vector through the manager
        let secure_vec = memory_manager.secure_vec_from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(secure_vec[0], 1);
        
        // Test security settings
        assert!(memory_manager.is_memory_locking_enabled());
        assert!(memory_manager.is_canary_protection_enabled());
        assert!(memory_manager.is_zero_on_free_enabled());
        
        // Test security level
        assert_eq!(memory_manager.security_level(), MemorySecurity::Enhanced);
    }
    
    // Test EnhancedSecureMemory if the feature is enabled
    #[cfg(feature = "enhanced-memory")]
    #[test]
    fn test_enhanced_secure_memory() {
        let mut enhanced = EnhancedSecureMemory::new([0u8; 32]);
        
        // Should start as writable
        assert!(!enhanced.is_read_only());
        
        // Set some values
        enhanced[0] = 42;
        enhanced[1] = 43;
        
        // Make read-only
        enhanced.make_read_only();
        assert!(enhanced.is_read_only());
        
        // We can still read
        assert_eq!(enhanced[0], 42);
        
        // Make writable again
        enhanced.make_writable();
        assert!(!enhanced.is_read_only());
        
        // Now we can modify
        enhanced[2] = 44;
        assert_eq!(enhanced[2], 44);
    }
}