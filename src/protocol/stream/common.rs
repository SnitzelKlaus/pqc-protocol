/*!
Common streaming utilities for the PQC protocol.
This module provides helper functions for encrypting and decrypting data chunks
using a PqcSession.
*/

use crate::core::{
    error::Result,
    session::PqcSession,
};

/// Encrypts a chunk of data using the provided session.
pub fn encrypt_chunk(session: &mut PqcSession, chunk: &[u8]) -> Result<Vec<u8>> {
    session.encrypt_and_sign(chunk)
}

/// Decrypts a chunk of data using the provided session.
pub fn decrypt_chunk(session: &mut PqcSession, chunk: &[u8]) -> Result<Vec<u8>> {
    session.verify_and_decrypt(chunk)
}