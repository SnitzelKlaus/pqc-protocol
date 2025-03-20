/*!
Constants for cryptographic operations.

This module defines various constants used throughout the crypto subsystem,
including key sizes, nonce sizes, salt values, etc.
*/

/// ChaCha20-Poly1305 constants
pub mod chacha {
    /// Size of ChaCha20-Poly1305 key in bytes
    pub const KEY_SIZE: usize = 32;
    
    /// Size of ChaCha20-Poly1305 nonce in bytes
    pub const NONCE_SIZE: usize = 12;
    
    /// Size of ChaCha20-Poly1305 tag in bytes
    pub const TAG_SIZE: usize = 16;
}

/// AES-GCM constants
pub mod aes {
    /// Size of AES-256-GCM key in bytes
    pub const KEY_SIZE: usize = 32;
    
    /// Size of AES-256-GCM nonce in bytes
    pub const NONCE_SIZE: usize = 12;
    
    /// Size of AES-256-GCM tag in bytes
    pub const TAG_SIZE: usize = 16;
}

/// Kyber constants
pub mod kyber {
    /// Size of Kyber768 public key in bytes
    pub const PUBLIC_KEY_BYTES: usize = 1184;
    
    /// Size of Kyber768 secret key in bytes
    pub const SECRET_KEY_BYTES: usize = 2400;
    
    /// Size of Kyber768 ciphertext in bytes
    pub const CIPHERTEXT_BYTES: usize = 1088;
    
    /// Size of Kyber768 shared secret in bytes
    pub const SHARED_SECRET_BYTES: usize = 32;
}

/// Dilithium constants
pub mod dilithium {
    /// Size of Dilithium3 public key in bytes
    pub const PUBLIC_KEY_BYTES: usize = 1952;
    
    /// Size of Dilithium3 secret key in bytes
    pub const SECRET_KEY_BYTES: usize = 4016;
    
    /// Size of Dilithium3 signature in bytes
    pub const SIGNATURE_BYTES: usize = 3293;
}

/// Salt value for HKDF (used for key derivation)
pub const HKDF_SALT: &[u8] = b"PQC-CRYPTO-SALT-VALUE-2023";

/// Info value for HKDF with ChaCha20-Poly1305
pub const HKDF_INFO_CHACHA: &[u8] = b"PQC-KDF-CHACHA20POLY1305";

/// Info value for HKDF with AES-256-GCM
pub const HKDF_INFO_AES: &[u8] = b"PQC-KDF-AES256GCM";