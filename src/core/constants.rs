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
    
    /// CRYSTALS-Kyber (Kyber768) constants
    pub mod kyber {
        /// Size of Kyber public key in bytes
        pub const PUBLIC_KEY_BYTES: usize = 1184;
        
        /// Size of Kyber secret key in bytes
        pub const SECRET_KEY_BYTES: usize = 2400;
        
        /// Size of Kyber ciphertext in bytes
        pub const CIPHERTEXT_BYTES: usize = 1088;
        
        /// Size of Kyber shared secret in bytes
        pub const SHARED_SECRET_BYTES: usize = 32;
    }
    
    /// CRYSTALS-Dilithium (dilithium3) constants
    pub mod dilithium {
        /// Size of Dilithium public key in bytes
        pub const PUBLIC_KEY_BYTES: usize = 1952;
        
        /// Size of Dilithium secret key in bytes
        pub const SECRET_KEY_BYTES: usize = 4016;
        
        /// Size of Dilithium signature in bytes
        pub const SIGNATURE_BYTES: usize = 3293;
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
}

/// Default salt for HKDF key derivation
pub const HKDF_SALT: &[u8] = b"PQC-Protocol-v1-Key-Derivation";

/// Info string for HKDF key derivation for ChaCha20-Poly1305
pub const HKDF_INFO_CHACHA: &[u8] = b"ChaCha20Poly1305";