/*!
Shared utility functions for the PQC protocol.

This module provides utility functions that can be used by both
synchronous and asynchronous implementations.
*/

use crate::core::{
    constants::MAX_CHUNK_SIZE,
    error::Result,
    session::PqcSession,
};

/// Calculate the number of chunks needed for a given data size
pub fn calculate_chunks(data_size: usize, chunk_size: usize) -> usize {
    (data_size + chunk_size - 1) / chunk_size
}

/// Safe version of calculate_chunks that uses a default chunk size
pub fn safe_calculate_chunks(data_size: usize, chunk_size: Option<usize>) -> usize {
    let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
    calculate_chunks(data_size, chunk_size)
}

/// Calculate the estimated encryption overhead for a given data size
pub fn estimate_encryption_overhead(data_size: usize) -> usize {
    // Estimate based on message header and authentication tag
    const HEADER_SIZE: usize = 10;
    const AUTH_TAG_SIZE: usize = 16;
    const SIGNATURE_SIZE: usize = 3293; // Dilithium3 signature size
    
    HEADER_SIZE + AUTH_TAG_SIZE + SIGNATURE_SIZE
}

/// Calculate the estimated message size after encryption
pub fn estimate_encrypted_size(data_size: usize) -> usize {
    data_size + estimate_encryption_overhead(data_size)
}

/// Calculate the estimated total size for chunked data
pub fn estimate_chunked_size(data_size: usize, chunk_size: Option<usize>) -> usize {
    let chunk_size = chunk_size.unwrap_or(MAX_CHUNK_SIZE);
    let chunks = safe_calculate_chunks(data_size, Some(chunk_size));
    chunks * estimate_encryption_overhead(chunk_size) + data_size
}

/// Check if key rotation is needed based on the session stats
pub fn should_rotate(session: &PqcSession) -> bool {
    session.should_rotate_keys()
}

/// Utility for parsing chunk sizes
pub fn parse_chunk_size(size: Option<usize>) -> usize {
    size.unwrap_or(MAX_CHUNK_SIZE)
}

/// Calculate the optimal chunk size for a given data size and resource constraints
pub fn calculate_optimal_chunk_size(data_size: usize, memory_limit: Option<usize>) -> usize {
    let memory_limit = memory_limit.unwrap_or(1024 * 1024); // Default to 1MB
    
    if data_size <= memory_limit {
        // If data fits in memory, use a reasonable chunk size
        return std::cmp::min(data_size, MAX_CHUNK_SIZE);
    }
    
    // Otherwise, use a chunk size that balances efficiency and memory usage
    // Use at most 1/4 of the memory limit for each chunk
    let max_chunk = memory_limit / 4;
    std::cmp::min(max_chunk, MAX_CHUNK_SIZE)
}

/// Validate chunk size and adjust if necessary
pub fn validate_chunk_size(requested_size: usize) -> usize {
    // Ensure chunk size is not too small
    const MIN_CHUNK_SIZE: usize = 1024; // 1KB minimum
    
    if requested_size < MIN_CHUNK_SIZE {
        return MIN_CHUNK_SIZE;
    }
    
    if requested_size > MAX_CHUNK_SIZE {
        return MAX_CHUNK_SIZE;
    }
    
    requested_size
}

/// Create chunks from data
pub fn create_chunks(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let validated_size = validate_chunk_size(chunk_size);
    data.chunks(validated_size).collect()
}

/// Builder pattern for configuring chunk settings
pub struct ChunkSettings {
    chunk_size: usize,
    memory_limit: Option<usize>,
    optimize: bool,
}

impl ChunkSettings {
    /// Create new chunk settings with default values
    pub fn new() -> Self {
        Self {
            chunk_size: MAX_CHUNK_SIZE,
            memory_limit: None,
            optimize: false,
        }
    }
    
    /// Set the chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = validate_chunk_size(size);
        self
    }
    
    /// Set the memory limit
    pub fn with_memory_limit(mut self, limit: usize) -> Self {
        self.memory_limit = Some(limit);
        self
    }
    
    /// Enable optimization
    pub fn optimize(mut self, enable: bool) -> Self {
        self.optimize = enable;
        self
    }
    
    /// Build the final chunk size
    pub fn build(self, data_size: usize) -> usize {
        if self.optimize && data_size > 0 {
            calculate_optimal_chunk_size(data_size, self.memory_limit)
        } else {
            self.chunk_size
        }
    }
}

impl Default for ChunkSettings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calculate_chunks() {
        assert_eq!(calculate_chunks(100, 10), 10);
        assert_eq!(calculate_chunks(101, 10), 11);
        assert_eq!(calculate_chunks(1000, 100), 10);
    }
    
    #[test]
    fn test_estimate_overhead() {
        let data_size = 1000;
        let overhead = estimate_encryption_overhead(data_size);
        
        // The overhead should be fixed and not depend on data size
        let data_size2 = 2000;
        let overhead2 = estimate_encryption_overhead(data_size2);
        
        assert_eq!(overhead, overhead2);
        assert!(overhead > 0);
    }
    
    #[test]
    fn test_estimate_encrypted_size() {
        let data_size = 1000;
        let encrypted_size = estimate_encrypted_size(data_size);
        
        assert!(encrypted_size > data_size);
        assert_eq!(encrypted_size, data_size + estimate_encryption_overhead(data_size));
    }
    
    #[test]
    fn test_validate_chunk_size() {
        assert_eq!(validate_chunk_size(500), 1024); // Too small, use minimum
        assert_eq!(validate_chunk_size(8192), 8192); // Valid size
        assert_eq!(validate_chunk_size(MAX_CHUNK_SIZE * 2), MAX_CHUNK_SIZE); // Too large, use maximum
    }
    
    #[test]
    fn test_chunk_settings() {
        let settings = ChunkSettings::new()
            .with_chunk_size(8192)
            .with_memory_limit(1_000_000)
            .optimize(true);
        
        let chunk_size = settings.build(10_000_000);
        
        // For a large data size, should choose an optimal chunk size
        assert!(chunk_size <= settings.memory_limit.unwrap() / 4);
        assert!(chunk_size <= MAX_CHUNK_SIZE);
        
        // Without optimization
        let settings_no_opt = ChunkSettings::new()
            .with_chunk_size(8192)
            .optimize(false);
        
        let chunk_size_no_opt = settings_no_opt.build(10_000_000);
        assert_eq!(chunk_size_no_opt, 8192);
    }
}