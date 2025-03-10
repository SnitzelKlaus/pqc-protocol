/*!
Core session implementation for the PQC protocol.
*/

use crate::{
    error::{Error, Result, auth_err, crypto_err, internal_err, key_exchange_err},
    header::MessageHeader,
    types::{MessageType, sizes},
};

use pqcrypto_kyber::{
    kyber768,
    kyber768::{
        PublicKey as KyberPublicKey,
        SecretKey as KyberSecretKey,
        Ciphertext as KyberCiphertext
    }
};

use pqcrypto_dilithium::{
    dilithium3,
    dilithium3::{
        PublicKey as DilithiumPublicKey,
        SecretKey as DilithiumSecretKey,
        Signature as DilithiumSignature
    }
};

use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as KemCiphertext},
    sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature},
};

use rand::{rngs::OsRng, RngCore};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, generic_array::GenericArray},
};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;

/// Session state for tracking connection progress
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is new, no keys exchanged
    New,
    /// Key exchange initiated (client side)
    KeyExchangeInitiated,
    /// Key exchange completed (server side after receiving client public key)
    KeyExchangeCompleted,
    /// Authentication initiated (verification keys exchanged)
    AuthenticationInitiated,
    /// Authentication completed (signatures verified)
    AuthenticationCompleted,
    /// Session established and ready for data transfer
    Established,
    /// Session closed
    Closed,
}

/// Endpoint role in the session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client role (initiates connection)
    Client,
    /// Server role (accepts connection)
    Server,
}

/// Post-Quantum Cryptography Session
///
/// This is the main class that handles the cryptographic operations for the protocol.
pub struct PqcSession {
    // Session state
    role: Role,
    state: SessionState,
    
    // Kyber keys for encryption
    local_secret_key: Option<KyberSecretKey>,
    remote_public_key: Option<KyberPublicKey>,
    
    // Dilithium keys for signatures
    local_signing_key: DilithiumSecretKey,
    local_verification_key: DilithiumPublicKey,
    remote_verification_key: Option<DilithiumPublicKey>,
    
    // Sequence numbers
    next_send_seq: u32,
    next_recv_seq: u32,
    
    // Shared symmetric key derived from Kyber key exchange
    shared_key: Option<[u8; 32]>,
    
    // ChaCha20-Poly1305 cipher
    cipher: Option<ChaCha20Poly1305>,
}

impl PqcSession {
    /// Create a new PQC session with a random Dilithium signing key
    pub fn new() -> Result<Self> {
        // Generate Dilithium keypair
        let (signing_key, verification_key) = dilithium3::keypair();
        
        Ok(Self {
            role: Role::Client, // Default to client, can be changed later
            state: SessionState::New,
            local_secret_key: None,
            remote_public_key: None,
            local_signing_key: signing_key,
            local_verification_key: verification_key,
            remote_verification_key: None,
            next_send_seq: 0,
            next_recv_seq: 0,
            shared_key: None,
            cipher: None,
        })
    }
    
    /// Create a new PQC session with a provided Dilithium signing key
    pub fn with_signing_key(signing_key: DilithiumSecretKey, verification_key: DilithiumPublicKey) -> Result<Self> {
        Ok(Self {
            role: Role::Client, // Default to client, can be changed later
            state: SessionState::New,
            local_secret_key: None,
            remote_public_key: None,
            local_signing_key: signing_key,
            local_verification_key: verification_key,
            remote_verification_key: None,
            next_send_seq: 0,
            next_recv_seq: 0,
            shared_key: None,
            cipher: None,
        })
    }
    
    /// Set the role of this session
    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }
    
    /// Get the current state of the session
    pub fn state(&self) -> SessionState {
        self.state
    }
    
    /// Get the role of this session
    pub fn role(&self) -> Role {
        self.role
    }
    
    /// Initialize key exchange (client side)
    ///
    /// Generates a Kyber keypair and returns the public key to be sent to the server.
    pub fn init_key_exchange(&mut self) -> Result<KyberPublicKey> {
        if self.state != SessionState::New {
            return key_exchange_err("Session already initialized");
        }
        
        // Generate Kyber keypair
        let (public_key, secret_key) = kyber768::keypair();
        
        // Store secret key
        self.local_secret_key = Some(secret_key);
        self.state = SessionState::KeyExchangeInitiated;
        
        Ok(public_key)
    }
    
    /// Process key exchange response (client side)
    ///
    /// Takes the ciphertext from the server and derives the shared key.
    pub fn process_key_exchange(&mut self, ciphertext: &KyberCiphertext) -> Result<()> {
        if self.state != SessionState::KeyExchangeInitiated {
            return key_exchange_err("Key exchange not initiated");
        }
        
        let secret_key = self.local_secret_key.as_ref()
            .ok_or_else(|| Error::Internal("Missing local secret key".into()))?;
        
        // Decapsulate to get the shared secret
        let shared_secret = kyber768::decapsulate(ciphertext, secret_key);
        
        // Use HKDF to derive encryption key from shared secret
        let encryption_key = self.derive_encryption_key(&shared_secret.as_bytes())?;
        
        // Store the shared key
        self.shared_key = Some(encryption_key);
        
        // Create cipher instance
        self.cipher = Some(ChaCha20Poly1305::new(Key::from_slice(&encryption_key)));
        
        // Update state
        self.state = SessionState::KeyExchangeCompleted;
        
        Ok(())
    }
    
    /// Accept key exchange (server side)
    ///
    /// Takes the client's public key, generates a shared secret, and returns the ciphertext.
    pub fn accept_key_exchange(&mut self, client_public_key: &KyberPublicKey) -> Result<KyberCiphertext> {
        if self.state != SessionState::New {
            return key_exchange_err("Session already initialized");
        }
        
        // Store remote public key
        self.remote_public_key = Some(client_public_key.clone());
        
        // Encapsulate to generate shared secret and ciphertext
        let (ciphertext, shared_secret) = kyber768::encapsulate(client_public_key);
        
        // Use HKDF to derive encryption key from shared secret
        let encryption_key = self.derive_encryption_key(&shared_secret.as_bytes())?;
        
        // Store the shared key
        self.shared_key = Some(encryption_key);
        
        // Create cipher instance
        self.cipher = Some(ChaCha20Poly1305::new(Key::from_slice(&encryption_key)));
        
        // Update state
        self.state = SessionState::KeyExchangeCompleted;
        
        Ok(ciphertext)
    }
    
    /// Sign data with our Dilithium signing key
    pub fn sign(&self, data: &[u8]) -> Result<DilithiumSignature> {
        Ok(dilithium3::detached_sign(data, &self.local_signing_key))
    }
    
    /// Verify signature with the remote verification key
    pub fn verify(&self, data: &[u8], signature: &DilithiumSignature) -> Result<()> {
        let verification_key = self.remote_verification_key.as_ref()
            .ok_or_else(|| Error::Authentication("No remote verification key available".into()))?;
        
        match dilithium3::verify_detached_signature(signature, data, verification_key) {
            Ok(_) => Ok(()),
            Err(_) => auth_err("Signature verification failed"),
        }
    }
    
    /// Set the remote verification key
    pub fn set_remote_verification_key(&mut self, key: DilithiumPublicKey) -> Result<()> {
        if self.state < SessionState::KeyExchangeCompleted {
            return auth_err("Key exchange must be completed before setting verification key");
        }
        
        self.remote_verification_key = Some(key);
        
        if self.state == SessionState::KeyExchangeCompleted {
            self.state = SessionState::AuthenticationInitiated;
        }
        
        Ok(())
    }
    
    /// Complete authentication
    pub fn complete_authentication(&mut self) -> Result<()> {
        if self.state != SessionState::AuthenticationInitiated {
            return auth_err("Authentication not initiated");
        }
        
        if self.remote_verification_key.is_none() {
            return auth_err("No remote verification key available");
        }
        
        self.state = SessionState::Established;
        Ok(())
    }
    
    /// Encrypt and sign data
    pub fn encrypt_and_sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::Established {
            return crypto_err("Session not established");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        // Create nonce from sequence number
        let nonce = self.create_nonce(self.next_send_seq, MessageType::Data);
        
        // Encrypt data
        let encrypted_data = match cipher.encrypt(&nonce, data) {
            Ok(ciphertext) => ciphertext,
            Err(_) => return crypto_err("Encryption failed"),
        };
        
        // Sign the encrypted data
        let signature = dilithium3::detached_sign(&encrypted_data, &self.local_signing_key);
        
        // Prepare message
        let mut buffer = Vec::with_capacity(
            sizes::HEADER_SIZE + encrypted_data.len() + signature.as_bytes().len()
        );
        
        // Add header
        let header = MessageHeader::new(
            MessageType::Data, 
            self.next_send_seq, 
            (encrypted_data.len() + signature.as_bytes().len()) as u32
        );
        buffer.extend_from_slice(&header.to_bytes());
        
        // Add encrypted data
        buffer.extend_from_slice(&encrypted_data);
        
        // Add signature
        buffer.extend_from_slice(signature.as_bytes());
        
        // Increment sequence number
        self.next_send_seq += 1;
        
        Ok(buffer)
    }
    
    /// Verify and decrypt data
    pub fn verify_and_decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if self.state != SessionState::Established {
            return crypto_err("Session not established");
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| Error::Internal("Cipher not initialized".into()))?;
        
        if message.len() < sizes::HEADER_SIZE {
            return format_err("Message too short for header");
        }
        
        // Parse header
        let header = MessageHeader::from_bytes(&message[..sizes::HEADER_SIZE])?;
        
        // Verify sequence number to prevent replay attacks
        if header.seq_num != self.next_recv_seq {
            return Err(Error::InvalidSequence);
        }
        
        // Verify message type
        if header.msg_type != MessageType::Data {
            return format_err(format!("Unexpected message type: {:?}", header.msg_type));
        }
        
        if message.len() < sizes::HEADER_SIZE + header.payload_len as usize {
            return format_err("Message too short for payload");
        }
        
        // Extract signature length - Dilithium signature size is fixed
        let signature_size = dilithium3::SIGNATURE_BYTES;
        
        if header.payload_len as usize <= signature_size {
            return format_err("Payload too small to contain signature and data");
        }
        
        // Extract encrypted data and signature
        let data_end = sizes::HEADER_SIZE + header.payload_len as usize - signature_size;
        let encrypted_data = &message[sizes::HEADER_SIZE..data_end];
        let signature_bytes = &message[data_end..sizes::HEADER_SIZE + header.payload_len as usize];
        
        // Convert signature bytes to Dilithium signature
        let signature = match DilithiumSignature::from_bytes(signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return format_err("Invalid signature format"),
        };
        
        // Verify signature
        if let Some(ref verification_key) = self.remote_verification_key {
            match dilithium3::verify_detached_signature(&signature, encrypted_data, verification_key) {
                Ok(_) => {},
                Err(_) => return auth_err("Signature verification failed"),
            }
        } else {
            return auth_err("No remote verification key available");
        }
        
        // Create nonce from sequence number
        let nonce = self.create_nonce(self.next_recv_seq, MessageType::Data);
        
        // Decrypt data
        let decrypted_data = match cipher.decrypt(&nonce, encrypted_data) {
            Ok(plaintext) => plaintext,
            Err(_) => return crypto_err("Decryption failed"),
        };
        
        // Increment sequence number
        self.next_recv_seq += 1;
        
        Ok(decrypted_data)
    }
    
    /// Generate acknowledgment message
    pub fn generate_ack(&mut self, seq_num: u32) -> Vec<u8> {
        let header = MessageHeader::new(MessageType::Ack, self.next_send_seq, 4);
        let mut buffer = Vec::with_capacity(sizes::HEADER_SIZE + 4);
        
        buffer.extend_from_slice(&header.to_bytes());
        buffer.extend_from_slice(&seq_num.to_be_bytes());
        
        self.next_send_seq += 1;
        buffer
    }
    
    /// Process acknowledgment message
    pub fn process_ack(&mut self, message: &[u8]) -> Result<u32> {
        if message.len() < sizes::HEADER_SIZE + 4 {
            return format_err("Acknowledgment message too short");
        }
        
        // Parse header
        let header = MessageHeader::from_bytes(&message[..sizes::HEADER_SIZE])?;
        
        // Verify message type
        if header.msg_type != MessageType::Ack {
            return format_err(format!("Unexpected message type: {:?}", header.msg_type));
        }
        
        // Extract acknowledged sequence number
        let mut seq_bytes = [0u8; 4];
        seq_bytes.copy_from_slice(&message[sizes::HEADER_SIZE..sizes::HEADER_SIZE + 4]);
        let seq_num = u32::from_be_bytes(seq_bytes);
        
        Ok(seq_num)
    }
    
    /// Close the session
    pub fn close(&mut self) -> Vec<u8> {
        let header = MessageHeader::new(MessageType::Close, self.next_send_seq, 0);
        let mut buffer = Vec::with_capacity(sizes::HEADER_SIZE);
        
        buffer.extend_from_slice(&header.to_bytes());
        
        self.state = SessionState::Closed;
        self.next_send_seq += 1;
        
        buffer
    }
    
    /// Get local verification key
    pub fn local_verification_key(&self) -> &DilithiumPublicKey {
        &self.local_verification_key
    }
    
    // Helper methods
    
    /// Create a nonce from sequence number and message type
    fn create_nonce(&self, seq_num: u32, msg_type: MessageType) -> Nonce {
        let mut nonce = [0u8; 12];
        
        // First 4 bytes: sequence number
        nonce[0..4].copy_from_slice(&seq_num.to_be_bytes());
        
        // 5th byte: message type
        nonce[4] = msg_type.as_u8();
        
        // Last 7 bytes: random data
        OsRng.fill_bytes(&mut nonce[5..]);
        
        *GenericArray::from_slice(&nonce)
    }
    
    /// Derive encryption key from shared secret using HKDF
    fn derive_encryption_key(&self, shared_secret: &[u8]) -> Result<[u8; 32]> {
        // Use HKDF to derive encryption key
        let salt = b"PQC-Protocol-v1-Key-Derivation";
        let info = b"ChaCha20Poly1305";
        
        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        
        let mut okm = [0u8; 32];
        if let Err(_) = hkdf.expand(info, &mut okm) {
            return crypto_err("HKDF key derivation failed");
        }
        
        Ok(okm)
    }
}

// Create a new error for format issues
fn format_err<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error::InvalidFormat(msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_exchange() {
        // Create client and server sessions
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        
        // Client initiates key exchange
        let client_public_key = client.init_key_exchange().unwrap();
        
        // Server accepts key exchange
        let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
        
        // Client processes server response
        client.process_key_exchange(&ciphertext).unwrap();
        
        // Both sides should now have a shared key
        assert!(client.shared_key.is_some());
        assert!(server.shared_key.is_some());
        
        // States should be updated
        assert_eq!(client.state(), SessionState::KeyExchangeCompleted);
        assert_eq!(server.state(), SessionState::KeyExchangeCompleted);
    }
    
    #[test]
    fn test_authentication() {
        // Create client and server sessions
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        
        // Complete key exchange
        let client_public_key = client.init_key_exchange().unwrap();
        let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
        client.process_key_exchange(&ciphertext).unwrap();
        
        // Exchange verification keys
        client.set_remote_verification_key(server.local_verification_key().clone()).unwrap();
        server.set_remote_verification_key(client.local_verification_key().clone()).unwrap();
        
        // Complete authentication
        client.complete_authentication().unwrap();
        server.complete_authentication().unwrap();
        
        // States should be updated
        assert_eq!(client.state(), SessionState::Established);
        assert_eq!(server.state(), SessionState::Established);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        // Create client and server sessions
        let mut client = PqcSession::new().unwrap();
        let mut server = PqcSession::new().unwrap();
        
        // Complete key exchange
        let client_public_key = client.init_key_exchange().unwrap();
        let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
        client.process_key_exchange(&ciphertext).unwrap();
        
        // Exchange verification keys
        client.set_remote_verification_key(server.local_verification_key().clone()).unwrap();
        server.set_remote_verification_key(client.local_verification_key().clone()).unwrap();
        
        // Complete authentication
        client.complete_authentication().unwrap();
        server.complete_authentication().unwrap();
        
        // Test data encryption and decryption
        let test_data = b"This is a test message";
        let encrypted = client.encrypt_and_sign(test_data).unwrap();
        let decrypted = server.verify_and_decrypt(&encrypted).unwrap();
        
        assert_eq!(test_data, &decrypted[..]);
    }
}