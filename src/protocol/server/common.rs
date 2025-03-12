/*!
Common functionality for PQC server operations.
This module factors out the common operations performed on a PqcSession for the server role.
*/

use crate::core::{
    error::{Result, Error, KeyExchangeError, AuthError},
    session::PqcSession,
    session::state::SessionState,
};

// Import the necessary traits to access their methods
use pqcrypto_traits::kem::{SharedSecret, PublicKey};
use pqcrypto_traits::sign::DetachedSignature;
use crate::core::security::rotation::PqcSessionKeyRotation;

/// Accept a connection by processing the client's public key.
/// Returns the ciphertext and local verification key as byte vectors.
pub fn accept(session: &mut PqcSession, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(client_public_key)
        .map_err(|_| Error::KeyExchange(KeyExchangeError::InvalidPublicKey))?;
    let ciphertext = session.accept_key_exchange(&pk)?;
    Ok((
        ciphertext.as_bytes().to_vec(),
        session.local_verification_key().as_bytes().to_vec(),
    ))
}

/// Complete authentication using the client's verification key.
pub fn authenticate(session: &mut PqcSession, client_verification_key: &[u8]) -> Result<()> {
    let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(client_verification_key)
        .map_err(|_| Error::Authentication(AuthError::InvalidKeyFormat))?;
    session.set_remote_verification_key(vk)?;
    session.complete_authentication()?;
    Ok(())
}

/// Encrypt and sign data for sending.
pub fn send(session: &mut PqcSession, data: &[u8]) -> Result<Vec<u8>> {
    let result = session.encrypt_and_sign(data)?;
    if session.should_rotate_keys() {
        session.track_sent(result.len());
    }
    Ok(result)
}

/// Verify and decrypt the received data.
pub fn receive(session: &mut PqcSession, encrypted: &[u8]) -> Result<Vec<u8>> {
    let result = session.verify_and_decrypt(encrypted)?;
    if session.should_rotate_keys() {
        session.track_received(encrypted.len());
    }
    Ok(result)
}

/// Close the session and return the closing message.
pub fn close(session: &mut PqcSession) -> Vec<u8> {
    session.close()
}

/// Check if key rotation is needed and, if so, return the rotation message.
pub fn check_rotation(session: &mut PqcSession) -> Result<Option<Vec<u8>>> {
    if session.should_rotate_keys() {
        let rotation_msg = session.initiate_key_rotation()?;
        Ok(Some(rotation_msg))
    } else {
        Ok(None)
    }
}

/// Process a key rotation message.
pub fn process_rotation(session: &mut PqcSession, rotation_msg: &[u8]) -> Result<Vec<u8>> {
    session.process_key_rotation(rotation_msg)
}

/// Complete key rotation using the server's response.
pub fn complete_rotation(session: &mut PqcSession, response: &[u8]) -> Result<()> {
    session.complete_key_rotation(response)
}

/// Get the current session state.
pub fn state(session: &PqcSession) -> SessionState {
    session.state()
}