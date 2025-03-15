/*!
Public API for memory management operations.

This module provides a simple and consistent API for memory management
operations, hiding the complexity of the underlying implementation.
*/

use crate::core::memory::manager::config::{MemoryConfig, for_current_platform};
use crate::core::memory::manager::memory_manager::SecureMemoryManager;
use crate::core::memory::containers::base_container::SecureContainer;
use crate::core::memory::containers::heap_container::SecureHeap;
use crate::core::memory::containers::readonly_container::ProtectedKey32;
use crate::core::memory::containers::stack_container::SecureStack;
use crate::core::memory::traits::zeroize::Zeroize;
use crate::core::memory::error::Result;

/// Global memory manager instance (lazily initialized)
static mut GLOBAL_MANAGER: Option<SecureMemoryManager> = None;

/// Get the global memory manager instance
fn get_global_manager() -> &'static SecureMemoryManager {
    unsafe {
        if GLOBAL_MANAGER.is_none() {
            GLOBAL_MANAGER = Some(for_current_platform().create_manager());
        }
        GLOBAL_MANAGER.as_ref().unwrap()
    }
}

/// Initialize the memory subsystem with default configuration
pub fn init() -> &'static SecureMemoryManager {
    get_global_manager()
}

/// Initialize the memory subsystem with custom configuration
pub fn init_with_config(config: MemoryConfig) -> SecureMemoryManager {
    config.create_manager()
}

/// Create a secure memory container for sensitive data
pub fn secure_memory<T>(value: T) -> SecureContainer<T> {
    get_global_manager().create_secure_container(value)
}

/// Create a secure vector for sensitive data
pub fn secure_vec<T>() -> SecureHeap<T> {
    get_global_manager().create_secure_heap()
}

/// Create a secure vector with capacity
pub fn secure_vec_with_capacity<T>(capacity: usize) -> SecureHeap<T> {
    let mut vec = get_global_manager().create_secure_heap::<T>();
    vec.reserve(capacity);
    vec
}

/// Create a secure vector from an existing vector
pub fn secure_vec_from_vec<T>(vec: Vec<T>) -> SecureHeap<T> {
    SecureHeap::from_vec(vec)
}

/// Create a secure heapless vector (stack-allocated)
pub fn secure_stack<T, const N: usize>() -> SecureStack<T, N> {
    get_global_manager().create_secure_stack()
}

/// Create a 32-byte secure key container
pub fn secure_key32(key_data: [u8; 32]) -> SecureContainer<[u8; 32]> {
    get_global_manager().create_secure_container(key_data)
}

/// Create a protected 32-byte key
pub fn protected_key32(key_data: [u8; 32]) -> ProtectedKey32 {
    get_global_manager().create_readonly_container(key_data)
}

/// Securely zero memory
pub fn zeroize<T: Zeroize>(value: &mut T) {
    value.zeroize();
}

/// Lock memory to prevent swapping
pub fn lock_memory(ptr: *const u8, size: usize) -> Result<()> {
    get_global_manager().lock_memory(ptr, size)
}

/// Unlock previously locked memory
pub fn unlock_memory(ptr: *const u8, size: usize) -> Result<()> {
    get_global_manager().unlock_memory(ptr, size)
}

/// Make memory read-only
pub fn make_memory_readonly(ptr: *const u8, size: usize) -> Result<()> {
    get_global_manager().protect_memory_readonly(ptr, size)
}

/// Make memory writable
pub fn make_memory_writable(ptr: *const u8, size: usize) -> Result<()> {
    get_global_manager().protect_memory_readwrite(ptr, size)
}

/// Generate random data
pub fn generate_random(length: usize) -> Result<Vec<u8>> {
    get_global_manager().generate_random_with_hsm(length)
}

/// Compare two byte slices in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    get_global_manager().constant_time_eq(a, b)
}