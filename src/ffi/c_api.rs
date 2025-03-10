/*!
C API for the PQC protocol.

This module provides C-compatible bindings to the PQC protocol,
exposing the core functionality through a C API.
*/

use crate::{
    PqcSession,
    error::Result,
    types::sizes,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as KemCiphertext},
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature},
};
use std::{
    ffi::c_void,
    os::raw::{c_char, c_int, c_uint},
    ptr, slice,
};

// Error codes for the C API
#[repr(C)]
pub enum PqcErrorCode {
    Success = 0,
    InvalidArgument = -1,
    CryptoError = -2,
    AuthError = -3,
    SessionError = -4,
    IoError = -5,
    InternalError = -6,
}

// Opaque session handle for the C API
#[repr(C)]
pub struct PqcSessionHandle(*mut c_void);

// Helper function to convert Result to C error code
fn to_error_code<T>(result: Result<T>) -> (PqcErrorCode, Option<T>) {
    match result {
        Ok(value) => (PqcErrorCode::Success, Some(value)),
        Err(err) => {
            let code = match err {
                crate::error::Error::Io(_) => PqcErrorCode::IoError,
                crate::error::Error::Protocol(_) => PqcErrorCode::SessionError,
                crate::error::Error::Crypto(_) => PqcErrorCode::CryptoError,
                crate::error::Error::InvalidSequence => PqcErrorCode::SessionError,
                crate::error::Error::InvalidFormat(_) => PqcErrorCode::InvalidArgument,
                crate::error::Error::Authentication(_) => PqcErrorCode::AuthError,
                crate::error::Error::SessionNotInitialized => PqcErrorCode::SessionError,
                crate::error::Error::UnsupportedVersion(_) => PqcErrorCode::SessionError,
                crate::error::Error::Internal(_) => PqcErrorCode::InternalError,
                crate::error::Error::KeyExchange(_) => PqcErrorCode::SessionError,
            };
            (code, None)
        }
    }
}

/// Create a new PQC session
///
/// @return A handle to the new session, or NULL on error
#[no_mangle]
pub extern "C" fn pqc_create_session() -> PqcSessionHandle {
    match PqcSession::new() {
        Ok(session) => {
            let boxed = Box::new(session);
            PqcSessionHandle(Box::into_raw(boxed) as *mut c_void)
        }
        Err(_) => PqcSessionHandle(ptr::null_mut()),
    }
}

/// Destroy a PQC session and free all associated resources
///
/// @param handle Handle to the session to destroy
#[no_mangle]
pub extern "C" fn pqc_destroy_session(handle: PqcSessionHandle) {
    if !handle.0.is_null() {
        unsafe {
            let _ = Box::from_raw(handle.0 as *mut PqcSession);
        }
    }
}

/// Initialize a key exchange (client side)
///
/// @param handle Session handle
/// @param out_public_key Buffer to receive the public key (must be at least KYBER_PUBLIC_KEY_BYTES bytes)
/// @param out_public_key_len Pointer to receive the public key length
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_init_key_exchange(
    handle: PqcSessionHandle,
    out_public_key: *mut u8,
    out_public_key_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || out_public_key.is_null() || out_public_key_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    
    // Initialize key exchange
    let (code, public_key) = to_error_code(session.init_key_exchange());
    
    match (code, public_key) {
        (PqcErrorCode::Success, Some(pk)) => {
            let pk_bytes = pk.as_bytes();
            
            unsafe {
                *out_public_key_len = pk_bytes.len() as c_uint;
                ptr::copy_nonoverlapping(
                    pk_bytes.as_ptr(),
                    out_public_key,
                    pk_bytes.len(),
                );
            }
            
            PqcErrorCode::Success as c_int
        }
        (code, _) => code as c_int,
    }
}

/// Process a key exchange response (client side)
///
/// @param handle Session handle
/// @param ciphertext Buffer containing the ciphertext
/// @param ciphertext_len Length of the ciphertext buffer
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_process_key_exchange(
    handle: PqcSessionHandle,
    ciphertext: *const u8,
    ciphertext_len: c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || ciphertext.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    if ciphertext_len as usize != sizes::KYBER_CIPHERTEXT_BYTES {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let ciphertext_bytes = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len as usize) };
    
    // Convert bytes to KyberCiphertext
    match kyber768::Ciphertext::from_bytes(ciphertext_bytes) {
        Ok(ct) => {
            // Process key exchange
            let (code, _) = to_error_code(session.process_key_exchange(&ct));
            code as c_int
        }
        Err(_) => PqcErrorCode::InvalidArgument as c_int,
    }
}

/// Accept a key exchange request (server side)
///
/// @param handle Session handle
/// @param public_key Buffer containing the client's public key
/// @param public_key_len Length of the public key buffer
/// @param out_ciphertext Buffer to receive the ciphertext (must be at least KYBER_CIPHERTEXT_BYTES bytes)
/// @param out_ciphertext_len Pointer to receive the ciphertext length
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_accept_key_exchange(
    handle: PqcSessionHandle,
    public_key: *const u8,
    public_key_len: c_uint,
    out_ciphertext: *mut u8,
    out_ciphertext_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || public_key.is_null() || out_ciphertext.is_null() || out_ciphertext_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    if public_key_len as usize != sizes::KYBER_PUBLIC_KEY_BYTES {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let pk_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len as usize) };
    
    // Convert bytes to KyberPublicKey
    match kyber768::PublicKey::from_bytes(pk_bytes) {
        Ok(pk) => {
            // Accept key exchange
            let (code, ciphertext) = to_error_code(session.accept_key_exchange(&pk));
            
            match (code, ciphertext) {
                (PqcErrorCode::Success, Some(ct)) => {
                    let ct_bytes = ct.as_bytes();
                    
                    unsafe {
                        *out_ciphertext_len = ct_bytes.len() as c_uint;
                        ptr::copy_nonoverlapping(
                            ct_bytes.as_ptr(),
                            out_ciphertext,
                            ct_bytes.len(),
                        );
                    }
                    
                    PqcErrorCode::Success as c_int
                }
                (code, _) => code as c_int,
            }
        }
        Err(_) => PqcErrorCode::InvalidArgument as c_int,
    }
}

/// Encrypt and sign data
///
/// @param handle Session handle
/// @param data Buffer containing the data to encrypt
/// @param data_len Length of the data buffer
/// @param out_message Buffer to receive the encrypted message
/// @param out_message_len Pointer to receive the message length (in/out)
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_encrypt_and_sign(
    handle: PqcSessionHandle,
    data: *const u8,
    data_len: c_uint,
    out_message: *mut u8,
    out_message_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || data.is_null() || out_message.is_null() || out_message_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len as usize) };
    
    // Get buffer size
    let max_len = unsafe { *out_message_len };
    
    // Encrypt and sign
    let (code, message) = to_error_code(session.encrypt_and_sign(data_slice));
    
    match (code, message) {
        (PqcErrorCode::Success, Some(msg)) => {
            if msg.len() > max_len as usize {
                unsafe { *out_message_len = msg.len() as c_uint };
                return PqcErrorCode::IoError as c_int;
            }
            
            unsafe {
                *out_message_len = msg.len() as c_uint;
                ptr::copy_nonoverlapping(
                    msg.as_ptr(),
                    out_message,
                    msg.len(),
                );
            }
            
            PqcErrorCode::Success as c_int
        }
        (code, _) => code as c_int,
    }
}

/// Verify and decrypt data
///
/// @param handle Session handle
/// @param message Buffer containing the encrypted message
/// @param message_len Length of the message buffer
/// @param out_data Buffer to receive the decrypted data
/// @param out_data_len Pointer to receive the data length (in/out)
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_verify_and_decrypt(
    handle: PqcSessionHandle,
    message: *const u8,
    message_len: c_uint,
    out_data: *mut u8,
    out_data_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || message.is_null() || out_data.is_null() || out_data_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let message_slice = unsafe { slice::from_raw_parts(message, message_len as usize) };
    
    // Get buffer size
    let max_len = unsafe { *out_data_len };
    
    // Verify and decrypt
    let (code, data) = to_error_code(session.verify_and_decrypt(message_slice));
    
    match (code, data) {
        (PqcErrorCode::Success, Some(d)) => {
            if d.len() > max_len as usize {
                unsafe { *out_data_len = d.len() as c_uint };
                return PqcErrorCode::IoError as c_int;
            }
            
            unsafe {
                *out_data_len = d.len() as c_uint;
                ptr::copy_nonoverlapping(
                    d.as_ptr(),
                    out_data,
                    d.len(),
                );
            }
            
            PqcErrorCode::Success as c_int
        }
        (code, _) => code as c_int,
    }
}

/// Set the remote verification key
///
/// @param handle Session handle
/// @param key Buffer containing the verification key
/// @param key_len Length of the verification key buffer
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_set_remote_verification_key(
    handle: PqcSessionHandle,
    key: *const u8,
    key_len: c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || key.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    if key_len as usize != sizes::DILITHIUM_PUBLIC_KEY_BYTES {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len as usize) };
    
    // Convert bytes to DilithiumPublicKey
    match dilithium3::PublicKey::from_bytes(key_bytes) {
        Ok(vk) => {
            // Set verification key
            let (code, _) = to_error_code(session.set_remote_verification_key(vk));
            code as c_int
        }
        Err(_) => PqcErrorCode::InvalidArgument as c_int,
    }
}

/// Get the local verification key
///
/// @param handle Session handle
/// @param out_key Buffer to receive the verification key
/// @param out_key_len Pointer to receive the key length (in/out)
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_get_local_verification_key(
    handle: PqcSessionHandle,
    out_key: *mut u8,
    out_key_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || out_key.is_null() || out_key_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    let vk_bytes = session.local_verification_key().as_bytes();
    
    // Get buffer size
    let max_len = unsafe { *out_key_len };
    
    if vk_bytes.len() > max_len as usize {
        unsafe { *out_key_len = vk_bytes.len() as c_uint };
        return PqcErrorCode::IoError as c_int;
    }
    
    unsafe {
        *out_key_len = vk_bytes.len() as c_uint;
        ptr::copy_nonoverlapping(
            vk_bytes.as_ptr(),
            out_key,
            vk_bytes.len(),
        );
    }
    
    PqcErrorCode::Success as c_int
}

/// Complete authentication
///
/// @param handle Session handle
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_complete_authentication(handle: PqcSessionHandle) -> c_int {
    // Validate arguments
    if handle.0.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    
    // Complete authentication
    let (code, _) = to_error_code(session.complete_authentication());
    code as c_int
}

/// Generate an acknowledgment message
///
/// @param handle Session handle
/// @param seq_num Sequence number to acknowledge
/// @param out_ack Buffer to receive the acknowledgment message
/// @param out_ack_len Pointer to receive the message length (in/out)
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_generate_ack(
    handle: PqcSessionHandle,
    seq_num: c_uint,
    out_ack: *mut u8,
    out_ack_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || out_ack.is_null() || out_ack_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    
    // Generate acknowledgment
    let ack = session.generate_ack(seq_num);
    
    // Get buffer size
    let max_len = unsafe { *out_ack_len };
    
    if ack.len() > max_len as usize {
        unsafe { *out_ack_len = ack.len() as c_uint };
        return PqcErrorCode::IoError as c_int;
    }
    
    unsafe {
        *out_ack_len = ack.len() as c_uint;
        ptr::copy_nonoverlapping(
            ack.as_ptr(),
            out_ack,
            ack.len(),
        );
    }
    
    PqcErrorCode::Success as c_int
}

/// Close the session
///
/// @param handle Session handle
/// @param out_close Buffer to receive the close message
/// @param out_close_len Pointer to receive the message length (in/out)
/// @return 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn pqc_close(
    handle: PqcSessionHandle,
    out_close: *mut u8,
    out_close_len: *mut c_uint,
) -> c_int {
    // Validate arguments
    if handle.0.is_null() || out_close.is_null() || out_close_len.is_null() {
        return PqcErrorCode::InvalidArgument as c_int;
    }
    
    let session = unsafe { &mut *(handle.0 as *mut PqcSession) };
    
    // Close session
    let close = session.close();
    
    // Get buffer size
    let max_len = unsafe { *out_close_len };
    
    if close.len() > max_len as usize {
        unsafe { *out_close_len = close.len() as c_uint };
        return PqcErrorCode::IoError as c_int;
    }
    
    unsafe {
        *out_close_len = close.len() as c_uint;
        ptr::copy_nonoverlapping(
            close.as_ptr(),
            out_close,
            close.len(),
        );
    }
    
    PqcErrorCode::Success as c_int
}