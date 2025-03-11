/*!
Key rotation mechanism for the PQC protocol.

This module provides utilities for periodic key rotation in long-running sessions
to maintain forward secrecy and security.
*/

use std::time::{Duration, Instant};

use crate::{
    error::{Result, Error},
    session::PqcSession,
    crypto::{
        KeyExchange, Cipher, Authentication,
        KyberPublicKey, KyberSecretKey, KyberCiphertext,
    },
    message::{
        MessageType, MessageBuilder, MessageParser,
    },
};

/// Parameters for key rotation
#[derive(Debug, Clone)]
pub struct KeyRotationParams {
    /// How often to rotate keys (e.g., every 24 hours)
    pub rotation_interval: Duration,
    
    /// Maximum messages before forced rotation
    pub max_messages: u32,
    
    /// Maximum data bytes before forced rotation
    pub max_bytes: u64,
    
    /// Whether to force rotation on connection errors
    pub rotate_on_error: bool,
}

impl Default for KeyRotationParams {
    fn default() -> Self {
        Self {
            // Default: rotate keys every 24 hours
            rotation_interval: Duration::from_secs(24 * 60 * 60),
            
            // Default: rotate after 1 million messages
            max_messages: 1_000_000,
            
            // Default: rotate after 1GB of data
            max_bytes: 1_000_000_000,
            
            // Default: rotate on connection errors
            rotate_on_error: true,
        }
    }
}

/// Session stats for key rotation decisions
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// When the current keys were established
    pub last_rotation: Instant,
    
    /// Number of messages sent with current keys
    pub messages_sent: u32,
    
    /// Number of bytes sent with current keys
    pub bytes_sent: u64,
    
    /// Number of messages received with current keys
    pub messages_received: u32,
    
    /// Number of bytes received with current keys
    pub bytes_received: u64,
}

impl SessionStats {
    /// Create new session stats initialized with current time
    pub fn new() -> Self {
        Self {
            last_rotation: Instant::now(),
            ..Default::default()
        }
    }
    
    /// Reset stats for a new rotation
    pub fn reset(&mut self) {
        self.last_rotation = Instant::now();
        self.messages_sent = 0;
        self.bytes_sent = 0;
        self.messages_received = 0;
        self.bytes_received = 0;
    }
    
    /// Track a sent message
    pub fn track_sent(&mut self, bytes: usize) {
        self.messages_sent += 1;
        self.bytes_sent += bytes as u64;
    }
    
    /// Track a received message
    pub fn track_received(&mut self, bytes: usize) {
        self.messages_received += 1;
        self.bytes_received += bytes as u64;
    }
}

/// Key rotation manager for PQC sessions
pub struct KeyRotationManager {
    /// Parameters for when to rotate keys
    params: KeyRotationParams,
    
    /// Current session statistics
    stats: SessionStats,
    
    /// Whether rotation is in progress
    rotating: bool,
}

impl KeyRotationManager {
    /// Create a new key rotation manager with default parameters
    pub fn new() -> Self {
        Self {
            params: KeyRotationParams::default(),
            stats: SessionStats::new(),
            rotating: false,
        }
    }
    
    /// Create a new key rotation manager with specific parameters
    pub fn with_params(params: KeyRotationParams) -> Self {
        Self {
            params,
            stats: SessionStats::new(),
            rotating: false,
        }
    }
    
    /// Check if rotation is needed
    pub fn should_rotate(&self) -> bool {
        if self.rotating {
            return false;
        }
        
        // Check time since last rotation
        let elapsed = self.stats.last_rotation.elapsed();
        if elapsed >= self.params.rotation_interval {
            return true;
        }
        
        // Check message count
        if self.stats.messages_sent >= self.params.max_messages {
            return true;
        }
        
        // Check data volume
        if self.stats.bytes_sent >= self.params.max_bytes {
            return true;
        }
        
        false
    }
    
    /// Track sent message
    pub fn track_sent(&mut self, bytes: usize) {
        self.stats.track_sent(bytes);
    }
    
    /// Track received message
    pub fn track_received(&mut self, bytes: usize) {
        self.stats.track_received(bytes);
    }
    
    /// Reset stats after rotation
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
    
    /// Get current stats
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }
    
    /// Get rotation parameters
    pub fn params(&self) -> &KeyRotationParams {
        &self.params
    }
    
    /// Update rotation parameters
    pub fn set_params(&mut self, params: KeyRotationParams) {
        self.params = params;
    }
    
    /// Mark rotation as in progress
    pub fn begin_rotation(&mut self) {
        self.rotating = true;
    }
    
    /// Mark rotation as complete
    pub fn complete_rotation(&mut self) {
        self.rotating = false;
        self.reset_stats();
    }
}

/// Extension trait to add key rotation to PqcSession
pub trait PqcSessionKeyRotation {
    /// Check if key rotation is needed
    fn should_rotate_keys(&self) -> bool;
    
    /// Track sent message
    fn track_sent(&mut self, bytes: usize);
    
    /// Track received message
    fn track_received(&mut self, bytes: usize);
    
    /// Initiate key rotation - returns rotation message to send
    fn initiate_key_rotation(&mut self) -> Result<Vec<u8>>;
    
    /// Process key rotation request
    fn process_key_rotation(&mut self, message: &[u8]) -> Result<Vec<u8>>;
    
    /// Complete key rotation based on response
    fn complete_key_rotation(&mut self, message: &[u8]) -> Result<()>;
    
    /// Get session statistics
    fn get_stats(&self) -> &SessionStats;
    
    /// Get key rotation parameters
    fn get_rotation_params(&self) -> &KeyRotationParams;
    
    /// Set key rotation parameters
    fn set_rotation_params(&mut self, params: KeyRotationParams);
}

/// Sample implementation for automatic key rotation
///
/// This function demonstrates how the session would handle automatic key rotation
/// in a real-world application. You would need to call this function periodically
/// in your application to check if rotation is needed.
pub fn handle_auto_rotation(session: &mut PqcSession) -> Result<Option<Vec<u8>>> {
    if session.should_rotate_keys() {
        // Initiate rotation and return message to send
        let rotation_message = session.initiate_key_rotation()?;
        return Ok(Some(rotation_message));
    }
    
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    
    #[test]
    fn test_key_rotation_manager() {
        // Create a manager with custom parameters for testing
        let params = KeyRotationParams {
            rotation_interval: Duration::from_millis(100), // Very short for testing
            max_messages: 5,
            max_bytes: 1000,
            rotate_on_error: true,
        };
        
        let mut manager = KeyRotationManager::with_params(params);
        
        // Initially should not need rotation
        assert!(!manager.should_rotate());
        
        // Test time-based rotation
        sleep(Duration::from_millis(150));
        assert!(manager.should_rotate());
        
        // Reset stats
        manager.reset_stats();
        assert!(!manager.should_rotate());
        
        // Test message count-based rotation
        for _ in 0..4 {
            manager.track_sent(10);
            assert!(!manager.should_rotate());
        }
        
        // This should trigger rotation (5 messages)
        manager.track_sent(10);
        assert!(manager.should_rotate());
        
        // Reset stats
        manager.reset_stats();
        assert!(!manager.should_rotate());
        
        // Test data volume-based rotation
        manager.track_sent(999);
        assert!(!manager.should_rotate());
        
        // This should trigger rotation (over 1000 bytes)
        manager.track_sent(10);
        assert!(manager.should_rotate());
    }
}