/*!
Error types for memory operations.

This module defines the various error types that can occur during secure
memory operations.
*/

use std::fmt;

/// Error type for memory operations
#[derive(Debug)]
pub enum Error {
    /// Failed to lock memory
    LockFailed(String),
    
    /// Failed to protect memory
    ProtectionFailed(String),
    
    /// Buffer overflow detected
    BufferOverflow,
    
    /// Canary value corruption
    CanaryCorruption {
        expected: u64,
        actual: u64,
        location: &'static str,
    },
    
    /// Hardware security module error
    #[cfg(feature = "hardware-security")]
    HsmError(String),
    
    /// Allocation failed
    AllocationFailed(std::alloc::Layout),
    
    /// Layout error
    LayoutError(String),
    
    /// Platform-specific error
    PlatformError(String),
    
    /// General error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LockFailed(msg) => write!(f, "Failed to lock memory: {}", msg),
            Error::ProtectionFailed(msg) => write!(f, "Failed to protect memory: {}", msg),
            Error::BufferOverflow => write!(f, "Buffer overflow detected"),
            Error::CanaryCorruption { expected, actual, location } => {
                write!(f, "Canary corruption detected at {}: expected 0x{:x}, found 0x{:x}", 
                    location, expected, actual)
            },
            #[cfg(feature = "hardware-security")]
            Error::HsmError(msg) => write!(f, "HSM error: {}", msg),
            Error::AllocationFailed(layout) => {
                write!(f, "Memory allocation failed for layout: size={}, align={}", 
                    layout.size(), layout.align())
            },
            Error::LayoutError(msg) => write!(f, "Memory layout error: {}", msg),
            Error::PlatformError(msg) => write!(f, "Platform error: {}", msg),
            Error::Other(msg) => write!(f, "Memory error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for memory operations
pub type Result<T> = std::result::Result<T, Error>;