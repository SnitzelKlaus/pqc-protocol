/*!
WebAssembly bindings for the PQC protocol.
*/

use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array, Error as JsError};
use web_sys::console;

use crate::PqcSession;
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as KemCiphertext},
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature},
};

/// WebAssembly wrapper for the PQC protocol session
#[wasm_bindgen]
pub struct WasmPqcSession {
    session: PqcSession,
}

#[wasm_bindgen]
impl WasmPqcSession {
    /// Create a new PQC session
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmPqcSession, JsValue> {
        // Set up panic hook for better error messages
        console_error_panic_hook::set_once();
        
        match PqcSession::new() {
            Ok(session) => Ok(Self { session }),
            Err(e) => Err(JsError::new(&format!("Failed to create session: {}", e)).into()),
        }
    }
    
    /// Initialize key exchange (client side)
    ///
    /// Returns the public key to be sent to the server.
    #[wasm_bindgen]
    pub fn init_key_exchange(&mut self) -> Result<Uint8Array, JsValue> {
        match self.session.init_key_exchange() {
            Ok(pk) => {
                let pk_bytes = pk.as_bytes();
                let result = Uint8Array::new_with_length(pk_bytes.len() as u32);
                result.copy_from(pk_bytes);
                Ok(result)
            },
            Err(e) => Err(JsError::new(&format!("Key exchange init failed: {}", e)).into()),
        }
    }
    
    /// Process key exchange response (client side)
    ///
    /// Takes the ciphertext from the server and derives the shared key.
    #[wasm_bindgen]
    pub fn process_key_exchange(&mut self, ciphertext: &Uint8Array) -> Result<(), JsValue> {
        let ct_bytes = ciphertext.to_vec();
        
        match kyber768::Ciphertext::from_bytes(&ct_bytes) {
            Ok(ct) => {
                match self.session.process_key_exchange(&ct) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(JsError::new(&format!("Key exchange processing failed: {}", e)).into()),
                }
            },
            Err(_) => Err(JsError::new("Invalid ciphertext format").into()),
        }
    }
    
    /// Accept key exchange (server side)
    ///
    /// Takes the client's public key and returns a ciphertext.
    #[wasm_bindgen]
    pub fn accept_key_exchange(&mut self, public_key: &Uint8Array) -> Result<Uint8Array, JsValue> {
        let pk_bytes = public_key.to_vec();
        
        match kyber768::PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => {
                match self.session.accept_key_exchange(&pk) {
                    Ok(ct) => {
                        let ct_bytes = ct.as_bytes();
                        let result = Uint8Array::new_with_length(ct_bytes.len() as u32);
                        result.copy_from(ct_bytes);
                        Ok(result)
                    },
                    Err(e) => Err(JsError::new(&format!("Key exchange acceptance failed: {}", e)).into()),
                }
            },
            Err(_) => Err(JsError::new("Invalid public key format").into()),
        }
    }
    
    /// Get the local verification key
    #[wasm_bindgen]
    pub fn get_local_verification_key(&self) -> Uint8Array {
        let vk_bytes = self.session.local_verification_key().as_bytes();
        let result = Uint8Array::new_with_length(vk_bytes.len() as u32);
        result.copy_from(vk_bytes);
        result
    }
    
    /// Set the remote verification key
    #[wasm_bindgen]
    pub fn set_remote_verification_key(&mut self, key: &Uint8Array) -> Result<(), JsValue> {
        let vk_bytes = key.to_vec();
        
        match dilithium3::PublicKey::from_bytes(&vk_bytes) {
            Ok(vk) => {
                match self.session.set_remote_verification_key(vk) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(JsError::new(&format!("Setting verification key failed: {}", e)).into()),
                }
            },
            Err(_) => Err(JsError::new("Invalid verification key format").into()),
        }
    }
    
    /// Complete authentication
    #[wasm_bindgen]
    pub fn complete_authentication(&mut self) -> Result<(), JsValue> {
        match self.session.complete_authentication() {
            Ok(_) => Ok(()),
            Err(e) => Err(JsError::new(&format!("Authentication completion failed: {}", e)).into()),
        }
    }
    
    /// Encrypt and sign data
    #[wasm_bindgen]
    pub fn encrypt_and_sign(&mut self, data: &Uint8Array) -> Result<Uint8Array, JsValue> {
        let data_bytes = data.to_vec();
        
        match self.session.encrypt_and_sign(&data_bytes) {
            Ok(encrypted) => {
                let result = Uint8Array::new_with_length(encrypted.len() as u32);
                result.copy_from(&encrypted);
                Ok(result)
            },
            Err(e) => Err(JsError::new(&format!("Encryption and signing failed: {}", e)).into()),
        }
    }
    
    /// Verify and decrypt data
    #[wasm_bindgen]
    pub fn verify_and_decrypt(&mut self, message: &Uint8Array) -> Result<Uint8Array, JsValue> {
        let message_bytes = message.to_vec();
        
        match self.session.verify_and_decrypt(&message_bytes) {
            Ok(decrypted) => {
                let result = Uint8Array::new_with_length(decrypted.len() as u32);
                result.copy_from(&decrypted);
                Ok(result)
            },
            Err(e) => Err(JsError::new(&format!("Verification and decryption failed: {}", e)).into()),
        }
    }
    
    /// Generate acknowledgment message
    #[wasm_bindgen]
    pub fn generate_ack(&mut self, seq_num: u32) -> Result<Uint8Array, JsValue> {
        let ack = self.session.generate_ack(seq_num);
        let result = Uint8Array::new_with_length(ack.len() as u32);
        result.copy_from(&ack);
        Ok(result)
    }
    
    /// Process acknowledgment message
    #[wasm_bindgen]
    pub fn process_ack(&mut self, message: &Uint8Array) -> Result<u32, JsValue> {
        let message_bytes = message.to_vec();
        
        match self.session.process_ack(&message_bytes) {
            Ok(seq_num) => Ok(seq_num),
            Err(e) => Err(JsError::new(&format!("Processing acknowledgment failed: {}", e)).into()),
        }
    }
    
    /// Close the session
    #[wasm_bindgen]
    pub fn close(&mut self) -> Result<Uint8Array, JsValue> {
        let close = self.session.close();
        let result = Uint8Array::new_with_length(close.len() as u32);
        result.copy_from(&close);
        Ok(result)
    }
}

/// Helper to create a WebAssembly stream sender
#[wasm_bindgen]
pub struct WasmPqcStreamSender {
    chunk_size: usize,
}

#[wasm_bindgen]
impl WasmPqcStreamSender {
    /// Create a new WebAssembly stream sender
    #[wasm_bindgen(constructor)]
    pub fn new(chunk_size: Option<u32>) -> Self {
        Self {
            chunk_size: chunk_size.unwrap_or(16384) as usize,
        }
    }
    
    /// Stream data in chunks
    #[wasm_bindgen]
    pub fn stream_data(&self, session: &mut WasmPqcSession, data: &Uint8Array) -> Result<Array, JsValue> {
        let data_bytes = data.to_vec();
        let result = Array::new();
        
        for chunk in data_bytes.chunks(self.chunk_size) {
            let chunk_array = Uint8Array::from(chunk);
            match session.encrypt_and_sign(&chunk_array) {
                Ok(encrypted) => {
                    result.push(&encrypted);
                },
                Err(e) => return Err(e),
            }
        }
        
        Ok(result)
    }
    
    /// Get the current chunk size
    #[wasm_bindgen]
    pub fn get_chunk_size(&self) -> u32 {
        self.chunk_size as u32
    }
    
    /// Set a new chunk size
    #[wasm_bindgen]
    pub fn set_chunk_size(&mut self, size: u32) {
        self.chunk_size = size as usize;
    }
}

/// Helper to receive streamed data
#[wasm_bindgen]
pub struct WasmPqcStreamReceiver {
    buffer: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmPqcStreamReceiver {
    /// Create a new WebAssembly stream receiver
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            buffer: None,
        }
    }
    
    /// Enable reassembly of chunks into a single buffer
    #[wasm_bindgen]
    pub fn enable_reassembly(&mut self) {
        if self.buffer.is_none() {
            self.buffer = Some(Vec::new());
        }
    }
    
    /// Disable reassembly and clear the buffer
    #[wasm_bindgen]
    pub fn disable_reassembly(&mut self) {
        self.buffer = None;
    }
    
    /// Process a chunk and add to reassembly buffer if enabled
    #[wasm_bindgen]
    pub fn process_chunk(&mut self, session: &mut WasmPqcSession, chunk: &Uint8Array) -> Result<Uint8Array, JsValue> {
        let decrypted = session.verify_and_decrypt(chunk)?;
        
        if let Some(ref mut buffer) = self.buffer {
            let data_bytes = decrypted.to_vec();
            buffer.extend_from_slice(&data_bytes);
        }
        
        Ok(decrypted)
    }
    
    /// Get the current reassembly buffer contents
    #[wasm_bindgen]
    pub fn get_reassembled_data(&self) -> Option<Uint8Array> {
        self.buffer.as_ref().map(|b| {
            let result = Uint8Array::new_with_length(b.len() as u32);
            result.copy_from(&b);
            result
        })
    }
    
    /// Take ownership of the reassembly buffer and clear it
    #[wasm_bindgen]
    pub fn take_reassembled_data(&mut self) -> Option<Uint8Array> {
        self.buffer.take().map(|b| {
            let result = Uint8Array::new_with_length(b.len() as u32);
            result.copy_from(&b);
            result
        })
    }
}

// Export constants to JavaScript
#[wasm_bindgen]
pub fn get_kyber_public_key_bytes() -> u32 {
    crate::types::sizes::KYBER_PUBLIC_KEY_BYTES as u32
}

#[wasm_bindgen]
pub fn get_kyber_ciphertext_bytes() -> u32 {
    crate::types::sizes::KYBER_CIPHERTEXT_BYTES as u32
}

#[wasm_bindgen]
pub fn get_dilithium_public_key_bytes() -> u32 {
    crate::types::sizes::DILITHIUM_PUBLIC_KEY_BYTES as u32
}

#[wasm_bindgen]
pub fn get_dilithium_signature_bytes() -> u32 {
    crate::types::sizes::DILITHIUM_SIGNATURE_BYTES as u32
}

#[wasm_bindgen]
pub fn get_max_chunk_size() -> u32 {
    crate::types::MAX_CHUNK_SIZE as u32
}

#[wasm_bindgen]
pub fn get_header_size() -> u32 {
    crate::types::sizes::HEADER_SIZE as u32
}

#[wasm_bindgen]
pub fn get_protocol_version() -> u8 {
    crate::VERSION
}

// Message type constants
#[wasm_bindgen]
pub fn get_message_type_key_exchange() -> u8 {
    crate::types::MessageType::KeyExchange as u8
}

#[wasm_bindgen]
pub fn get_message_type_signature() -> u8 {
    crate::types::MessageType::Signature as u8
}

#[wasm_bindgen]
pub fn get_message_type_data() -> u8 {
    crate::types::MessageType::Data as u8
}

#[wasm_bindgen]
pub fn get_message_type_ack() -> u8 {
    crate::types::MessageType::Ack as u8
}

#[wasm_bindgen]
pub fn get_message_type_close() -> u8 {
    crate::types::MessageType::Close as u8
}

#[wasm_bindgen]
pub fn get_message_type_error() -> u8 {
    crate::types::MessageType::Error as u8
}