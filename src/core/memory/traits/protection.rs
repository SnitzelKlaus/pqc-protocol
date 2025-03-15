/*!
Memory protection traits.

This module defines the traits for memory protection operations like locking,
setting read-only protection, and checking integrity.
*/

use crate::core::memory::error::Result;

/// Trait for memory protection operations
pub trait MemoryProtection {
    /// Enable memory locking to prevent swapping
    fn lock_memory(&mut self) -> Result<()>;
    
    /// Disable memory locking
    fn unlock_memory(&mut self) -> Result<()>;
    
    /// Check if memory is locked
    fn is_memory_locked(&self) -> bool;
    
    /// Make memory read-only
    fn make_read_only(&mut self) -> Result<()>;
    
    /// Make memory writable
    fn make_writable(&mut self) -> Result<()>;
    
    /// Check if memory is read-only
    fn is_read_only(&self) -> bool;
    
    /// Check for buffer overflows using canary values
    fn check_integrity(&self) -> Result<()>;
    
    /// Clear memory by filling with zeros
    fn clear(&mut self) -> Result<()>;
}