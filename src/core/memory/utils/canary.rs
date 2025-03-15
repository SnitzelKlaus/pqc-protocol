/*!
Canary value utilities for detecting buffer overflows.

This module provides functions for creating and checking canary values
to detect buffer overflows in secure memory containers.
*/

use rand::{Rng, thread_rng};
use crate::core::memory::error::{Error, Result};

/// Create a new random canary value
pub fn create_canary() -> u64 {
    thread_rng().gen::<u64>()
}

/// Check a pair of canary values for equality
pub fn check_canaries(front: u64, back: u64, expected: u64) -> Result<()> {
    if front != expected {
        return Err(Error::CanaryCorruption {
            expected,
            actual: front,
            location: "front",
        });
    }
    
    if back != expected {
        return Err(Error::CanaryCorruption {
            expected,
            actual: back,
            location: "back",
        });
    }
    
    Ok(())
}

/// A wrapper for a pair of canary values
#[derive(Debug, Clone, Copy)]
pub struct CanaryPair {
    /// The expected value
    pub value: u64,
    /// The front canary value
    pub front: u64,
    /// The back canary value
    pub back: u64,
}

impl CanaryPair {
    /// Create a new canary pair with a random value
    pub fn new() -> Self {
        let value = create_canary();
        Self {
            value,
            front: value,
            back: value,
        }
    }
    
    /// Create a new canary pair with a specific value
    pub fn with_value(value: u64) -> Self {
        Self {
            value,
            front: value,
            back: value,
        }
    }
    
    /// Check if the canary values match the expected value
    pub fn check(&self) -> Result<()> {
        check_canaries(self.front, self.back, self.value)
    }
    
    /// Reset the canary values to the expected value
    pub fn reset(&mut self) {
        self.front = self.value;
        self.back = self.value;
    }
    
    /// Generate a new random value and update all fields
    pub fn regenerate(&mut self) {
        self.value = create_canary();
        self.reset();
    }
}

impl Default for CanaryPair {
    fn default() -> Self {
        Self::new()
    }
}