/*!
Shared cryptographic operations for the PQC protocol.

This module provides common cryptographic operations that can be used
in both synchronous and asynchronous implementations.
*/

use crate::core::{
    error::Result,
    session::PqcSession,
};

/// Process the client's public key and generate server ciphertext.
///
/// This function is used by both sync and async server implementations.
pub fn accept(session: &mut PqcSession, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Load the public key
    let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(client_public_key)?;
    
    // Accept key exchange and get ciphertext
    let ciphertext = session.accept_key_exchange(&pk)?;
    
    // Return both the ciphertext and our verification key
    Ok((
        ciphertext.as_bytes().to_vec(),
        session.local_verification_key().as_bytes().to_vec(),
    ))
}

/// Encrypt data using the session.
///
/// This function is used by both sync and async client/server implementations.
pub fn encrypt(session: &mut PqcSession, data: &[u8]) -> Result<Vec<u8>> {
    session.encrypt_and_sign(data)
}

/// Decrypt data using the session.
///
/// This function is used by both sync and async client/server implementations.
pub fn decrypt(session: &mut PqcSession, encrypted: &[u8]) -> Result<Vec<u8>> {
    session.verify_and_decrypt(encrypted)
}

/// Authenticate with the remote party.
///
/// This function is used by both sync and async client/server implementations.
pub fn authenticate(session: &mut PqcSession, verification_key: &[u8]) -> Result<()> {
    // Load the verification key
    let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(verification_key)?;
    
    // Set the remote verification key
    session.set_remote_verification_key(vk)?;
    
    // Complete authentication
    session.complete_authentication()
}

/// Check for key rotation.
///
/// This function is used by both sync and async client/server implementations.
pub fn check_rotation(session: &mut PqcSession) -> Result<Option<Vec<u8>>> {
    if session.should_rotate_keys() {
        let rotation_msg = session.initiate_key_rotation()?;
        Ok(Some(rotation_msg))
    } else {
        Ok(None)
    }
}

/// Process a key rotation message.
///
/// This function is used by both sync and async client/server implementations.
pub fn process_rotation(session: &mut PqcSession, rotation_msg: &[u8]) -> Result<Vec<u8>> {
    session.process_key_rotation(rotation_msg)
}

/// Complete key rotation.
///
/// This function is used by both sync and async client/server implementations.
pub fn complete_rotation(session: &mut PqcSession, response: &[u8]) -> Result<()> {
    session.complete_key_rotation(response)
}

/// Encrypt a chunk of data.
///
/// This function is used by both sync and async stream implementations.
pub fn encrypt_chunk(session: &mut PqcSession, chunk: &[u8]) -> Result<Vec<u8>> {
    encrypt(session, chunk)
}

/// Decrypt a chunk of data.
///
/// This function is used by both sync and async stream implementations.
pub fn decrypt_chunk(session: &mut PqcSession, chunk: &[u8]) -> Result<Vec<u8>> {
    decrypt(session, chunk)
}

/// Initiate a key exchange and return the public key.
///
/// This function is used by both sync and async client implementations.
pub fn connect(session: &mut PqcSession) -> Result<Vec<u8>> {
    let public_key = session.init_key_exchange()?;
    Ok(public_key.as_bytes().to_vec())
}

/// Process server's ciphertext response and return client's verification key.
///
/// This function is used by both sync and async client implementations.
pub fn process_response(session: &mut PqcSession, ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Load the ciphertext
    let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)?;
    
    // Process the key exchange
    session.process_key_exchange(&ct)?;
    
    // Return our verification key
    Ok(session.local_verification_key().as_bytes().to_vec())
}

/// Generate a close message.
///
/// This function is used by both sync and async implementations.
pub fn close(session: &mut PqcSession) -> Vec<u8> {
    session.close()
}

/// A struct for handling common cryptographic operations
pub struct SharedCrypto {
    /// The session to use for cryptographic operations
    session: PqcSession,
}

impl SharedCrypto {
    /// Create a new SharedCrypto
    pub fn new(session: PqcSession) -> Self {
        Self { session }
    }
    
    /// Get a reference to the session
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the session
    pub fn session_mut(&mut self) -> &mut PqcSession {
        &mut self.session
    }
    
    /// Into the inner session
    pub fn into_inner(self) -> PqcSession {
        self.session
    }
    
    /// Server: Accept a connection
    pub fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        accept(&mut self.session, client_public_key)
    }
    
    /// Client: Connect to server
    pub fn connect(&mut self) -> Result<Vec<u8>> {
        connect(&mut self.session, )
    }
    
    /// Client: Process server response
    pub fn process_response(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        process_response(&mut self.session, ciphertext)
    }
    
    /// Authenticate with verification key
    pub fn authenticate(&mut self, verification_key: &[u8]) -> Result<()> {
        authenticate(&mut self.session, verification_key)
    }
    
    /// Encrypt data
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        encrypt(&mut self.session, data)
    }
    
    /// Decrypt data
    pub fn decrypt(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        decrypt(&mut self.session, encrypted)
    }
    
    /// Check for key rotation
    pub fn check_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        check_rotation(&mut self.session)
    }
    
    /// Process a key rotation message
    pub fn process_rotation(&mut self, rotation_msg: &[u8]) -> Result<Vec<u8>> {
        process_rotation(&mut self.session, rotation_msg)
    }
    
    /// Complete key rotation
    pub fn complete_rotation(&mut self, response: &[u8]) -> Result<()> {
        complete_rotation(&mut self.session, response)
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Vec<u8> {
        close(&mut self.session)
    }
}