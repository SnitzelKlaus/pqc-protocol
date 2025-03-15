/*!
Utility functions for memory operations.

This module provides various utility functions and wrapper types
for memory operations like zeroization, canary value management, etc.
*/

pub mod zeroize_on_drop;
pub mod constant_time;
pub mod canary;

// Re-export utility functions
pub use zeroize_on_drop::ZeroizeOnDrop;
pub use constant_time::constant_time_eq;