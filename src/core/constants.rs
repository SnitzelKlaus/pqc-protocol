/*!
Constants for the PQC protocol.

This module contains all protocol constants including message sizes,
key sizes, and other configurable values.
*/

/// Protocol version
pub const VERSION: u8 = 0x01;

/// Maximum chunk size for streaming data (16KB)
pub const MAX_CHUNK_SIZE: usize = 16384;

/// Size constants for the protocol
pub mod sizes {
    /// Size of the message header in bytes
    pub const HEADER_SIZE: usize = 10;
    
    /// CRYSTALS-Kyber constants
    pub mod kyber {
        /// Size of Kyber768 public key in bytes
        pub const PUBLIC_KEY_BYTES: usize = 1184;
        
        /// Size of Kyber768 secret key in bytes
        pub const SECRET_KEY_BYTES: usize = 2400;
        
        /// Size of Kyber768 ciphertext in bytes
        pub const CIPHERTEXT_BYTES: usize = 1088;
        
        /// Size of Kyber shared secret in bytes
        pub const SHARED_SECRET_BYTES: usize = 32;
        
        /// Size of Kyber512 public key in bytes (if enabled)
        #[cfg(feature = "kyber512")]
        pub const PUBLIC_KEY_BYTES_512: usize = 800;
        
        /// Size of Kyber512 ciphertext in bytes (if enabled)
        #[cfg(feature = "kyber512")]
        pub const CIPHERTEXT_BYTES_512: usize = 768;
        
        /// Size of Kyber1024 public key in bytes (if enabled)
        #[cfg(feature = "kyber1024")]
        pub const PUBLIC_KEY_BYTES_1024: usize = 1568;
        
        /// Size of Kyber1024 ciphertext in bytes (if enabled)
        #[cfg(feature = "kyber1024")]
        pub const CIPHERTEXT_BYTES_1024: usize = 1568;
    }
    
    /// CRYSTALS-Dilithium constants
    pub mod dilithium {
        /// Size of Dilithium3 public key in bytes
        pub const PUBLIC_KEY_BYTES: usize = 1952;
        
        /// Size of Dilithium3 secret key in bytes
        pub const SECRET_KEY_BYTES: usize = 4016;
        
        /// Size of Dilithium3 signature in bytes
        pub const SIGNATURE_BYTES: usize = 3293;
        
        /// Size of Dilithium2 public key in bytes (if enabled)
        #[cfg(feature = "dilithium2")]
        pub const PUBLIC_KEY_BYTES_2: usize = 1312;
        
        /// Size of Dilithium2 signature in bytes (if enabled)
        #[cfg(feature = "dilithium2")]
        pub const SIGNATURE_BYTES_2: usize = 2420;
        
        /// Size of Dilithium5 public key in bytes (if enabled)
        #[cfg(feature = "dilithium5")]
        pub const PUBLIC_KEY_BYTES_5: usize = 2592;
        
        /// Size of Dilithium5 signature in bytes (if enabled)
        #[cfg(feature = "dilithium5")]
        pub const SIGNATURE_BYTES_5: usize = 4595;
    }
    
    /// ChaCha20-Poly1305 constants
    pub mod chacha {
        /// Size of ChaCha20-Poly1305 authentication tag in bytes
        pub const TAG_SIZE: usize = 16;
        
        /// Size of ChaCha20-Poly1305 nonce in bytes
        pub const NONCE_SIZE: usize = 12;
        
        /// Size of ChaCha20-Poly1305 key in bytes
        pub const KEY_SIZE: usize = 32;
    }
    
    /// AES-GCM constants
    #[cfg(feature = "aes-gcm")]
    pub mod aes {
        /// Size of AES-256-GCM authentication tag in bytes
        pub const TAG_SIZE: usize = 16;
        
        /// Size of AES-256-GCM nonce in bytes
        pub const NONCE_SIZE: usize = 12;
        
        /// Size of AES-256-GCM key in bytes
        pub const KEY_SIZE: usize = 32;
    }
}

/// Default salt for HKDF key derivation
pub const HKDF_SALT: &[u8] = b"PQC-Protocol-v1-Key-Derivation";

/// Info string for HKDF key derivation for ChaCha20-Poly1305
pub const HKDF_INFO_CHACHA: &[u8] = b"ChaCha20Poly1305";

/// Info string for HKDF key derivation for AES-256-GCM
#[cfg(feature = "aes-gcm")]
pub const HKDF_INFO_AES: &[u8] = b"AES256GCM";

/// Configuration defaults
pub mod defaults {
    /// Default maximum message size
    pub const MAX_MESSAGE_SIZE: usize = 1_048_576; // 1 MB
    
    /// Default maximum key age in seconds
    pub const MAX_KEY_AGE_SECONDS: u64 = 86400; // 24 hours
    
    /// Default maximum messages per key
    pub const MAX_MESSAGES_PER_KEY: u32 = 1_000_000;
    
    /// Default maximum bytes per key
    pub const MAX_BYTES_PER_KEY: u64 = 1_000_000_000; // 1 GB
}

/// Protocol feature flags
pub mod features {
    /// Whether to allow key rotation
    pub const ALLOW_KEY_ROTATION: bool = true;
    
    /// Whether to set memory as secure (prevent swapping)
    pub const SECURE_MEMORY: bool = true;
    
    /// Whether to perform timing-safe comparisons
    pub const CONSTANT_TIME: bool = true;
}