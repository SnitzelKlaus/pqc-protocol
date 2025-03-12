/*!
Common functionality for PQC client operations.
This module factors out the common operations performed on a PqcSession.
*/

use crate::core::{
    error::{Result, Error, CryptoError, AuthError},
    session::PqcSession,
};

// Import the necessary traits to access their methods
use pqcrypto_traits::kem::{PublicKey, Ciphertext};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;

/// Initiate key exchange and return public key bytes.
pub fn connect(session: &mut PqcSession) -> Result<Vec<u8>> {
    let public_key = session.init_key_exchange()?;
    Ok(public_key.as_bytes().to_vec())
}

/// Process the server's response ciphertext and return the verification key bytes.
pub fn process_response(session: &mut PqcSession, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| Error::Crypto(CryptoError::InvalidKeyFormat))?;
    session.process_key_exchange(&ct)?;
    Ok(session.local_verification_key().as_bytes().to_vec())
}

/// Complete authentication using the server's verification key.
pub fn authenticate(session: &mut PqcSession, server_verification_key: &[u8]) -> Result<()> {
    let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(server_verification_key)
        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
    session.set_remote_verification_key(vk)?;
    session.complete_authentication()?;
    Ok(())
}

/// Encrypt and sign data for sending.
pub fn send(session: &mut PqcSession, data: &[u8]) -> Result<Vec<u8>> {
    session.encrypt_and_sign(data)
}

/// Verify and decrypt the received data.
pub fn receive(session: &mut PqcSession, encrypted: &[u8]) -> Result<Vec<u8>> {
    session.verify_and_decrypt(encrypted)
}

/// Close the session and return the closing message.
pub fn close(session: &mut PqcSession) -> Vec<u8> {
    session.close()
}

/// Check if key rotation is needed and, if so, return a rotation message.
pub fn check_rotation(session: &mut PqcSession) -> Result<Option<Vec<u8>>> {
    if session.should_rotate_keys() {
        let rotation_msg = session.initiate_key_rotation()?;
        Ok(Some(rotation_msg))
    } else {
        Ok(None)
    }
}

/// Process a key rotation message from the server.
pub fn process_rotation(session: &mut PqcSession, rotation_msg: &[u8]) -> Result<Vec<u8>> {
    session.process_key_rotation(rotation_msg)
}

/// Complete key rotation using the server's response.
pub fn complete_rotation(session: &mut PqcSession, response: &[u8]) -> Result<()> {
    session.complete_key_rotation(response)
}