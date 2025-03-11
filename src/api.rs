/*!
High-level API for the PQC protocol.

This module provides a simplified API for common protocol operations,
hiding implementation details and providing a more user-friendly interface.
*/

use crate::{
    error::Result,
    session::{PqcSession, Role, SessionState},
    streaming::{PqcStreamSender, PqcStreamReceiver},
    crypto::{KyberPublicKey, DilithiumPublicKey},
};

/// Client-side operations for the PQC protocol
pub struct PqcClient {
    /// The underlying session
    session: PqcSession,
}

impl PqcClient {
    /// Create a new PQC client
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Client);
        Ok(Self { session })
    }
    
    /// Start the connection process
    ///
    /// Initiates key exchange and returns the public key to send to the server.
    pub fn connect(&mut self) -> Result<Vec<u8>> {
        let public_key = self.session.init_key_exchange()?;
        Ok(public_key.as_bytes().to_vec())
    }
    
    /// Process the server's response to complete the connection
    ///
    /// Takes the ciphertext from the server and returns the verification key to send.
    pub fn process_response(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Convert bytes to Kyber ciphertext
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| crate::error::Error::Crypto("Invalid ciphertext format".into()))?;
        
        // Process the ciphertext
        self.session.process_key_exchange(&ct)?;
        
        // Return the verification key
        Ok(self.session.local_verification_key().as_bytes().to_vec())
    }
    
    /// Complete authentication with the server's verification key
    ///
    /// Takes the server's verification key and completes the connection.
    pub fn authenticate(&mut self, server_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(server_verification_key)
            .map_err(|_| crate::error::Error::Authentication("Invalid verification key format".into()))?;
        
        // Set the remote verification key
        self.session.set_remote_verification_key(vk)?;
        
        // Complete authentication
        self.session.complete_authentication()?;
        
        Ok(())
    }
    
    /// Send a message to the server
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.session.encrypt_and_sign(data)
    }
    
    /// Receive a message from the server
    pub fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.session.verify_and_decrypt(encrypted)
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Vec<u8> {
        self.session.close()
    }
    
    /// Stream data to the server
    pub fn stream<'a>(&'a mut self, data: &'a [u8], chunk_size: Option<usize>) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        let mut sender = PqcStreamSender::new(&mut self.session, chunk_size);
        sender.stream_data(data)
    }
    
    /// Create a stream receiver to reassemble chunked data
    pub fn create_receiver(&mut self) -> PqcStreamReceiver {
        PqcStreamReceiver::with_reassembly(&mut self.session)
    }
    
    /// Get the current connection state
    pub fn state(&self) -> SessionState {
        self.session.state()
    }
    
    /// Get a reference to the underlying session
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the underlying session
    pub fn session_mut(&mut self) -> &mut PqcSession {
        &mut self.session
    }
}

/// Server-side operations for the PQC protocol
pub struct PqcServer {
    /// The underlying session
    session: PqcSession,
}

impl PqcServer {
    /// Create a new PQC server
    pub fn new() -> Result<Self> {
        let mut session = PqcSession::new()?;
        session.set_role(Role::Server);
        Ok(Self { session })
    }
    
    /// Accept a connection from a client
    ///
    /// Takes the client's public key and returns the ciphertext and verification key to send back.
    pub fn accept(&mut self, client_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Convert bytes to Kyber public key
        let pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(client_public_key)
            .map_err(|_| crate::error::Error::Crypto("Invalid public key format".into()))?;
        
        // Accept the key exchange
        let ciphertext = self.session.accept_key_exchange(&pk)?;
        
        // Return the ciphertext and verification key
        Ok((
            ciphertext.as_bytes().to_vec(),
            self.session.local_verification_key().as_bytes().to_vec()
        ))
    }
    
    /// Complete authentication with the client's verification key
    ///
    /// Takes the client's verification key and completes the connection.
    pub fn authenticate(&mut self, client_verification_key: &[u8]) -> Result<()> {
        // Convert bytes to Dilithium verification key
        let vk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(client_verification_key)
            .map_err(|_| crate::error::Error::Authentication("Invalid verification key format".into()))?;
        
        // Set the remote verification key
        self.session.set_remote_verification_key(vk)?;
        
        // Complete authentication
        self.session.complete_authentication()?;
        
        Ok(())
    }
    
    /// Send a message to the client
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.session.encrypt_and_sign(data)
    }
    
    /// Receive a message from the client
    pub fn receive(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.session.verify_and_decrypt(encrypted)
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Vec<u8> {
        self.session.close()
    }
    
    /// Stream data to the client
    pub fn stream<'a>(&'a mut self, data: &'a [u8], chunk_size: Option<usize>) -> impl Iterator<Item = Result<Vec<u8>>> + 'a {
        let mut sender = PqcStreamSender::new(&mut self.session, chunk_size);
        sender.stream_data(data)
    }
    
    /// Create a stream receiver to reassemble chunked data
    pub fn create_receiver(&mut self) -> PqcStreamReceiver {
        PqcStreamReceiver::with_reassembly(&mut self.session)
    }
    
    /// Get the current connection state
    pub fn state(&self) -> SessionState {
        self.session.state()
    }
    
    /// Get a reference to the underlying session
    pub fn session(&self) -> &PqcSession {
        &self.session
    }
    
    /// Get a mutable reference to the underlying session
    pub fn session_mut(&mut self) -> &mut PqcSession {
        &mut self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_server_interaction() -> Result<()> {
        // Create client and server
        let mut client = PqcClient::new()?;
        let mut server = PqcServer::new()?;
        
        // Client connects and gets public key
        let client_pk = client.connect()?;
        
        // Server accepts connection and gets ciphertext and verification key
        let (server_ct, server_vk) = server.accept(&client_pk)?;
        
        // Client processes server response and gets own verification key
        let client_vk = client.process_response(&server_ct)?;
        
        // Server authenticates with client verification key
        server.authenticate(&client_vk)?;
        
        // Client authenticates with server verification key
        client.authenticate(&server_vk)?;
        
        // Test data exchange
        let test_message = b"Hello from the client!";
        let encrypted = client.send(test_message)?;
        let decrypted = server.receive(&encrypted)?;
        
        assert_eq!(test_message, &decrypted[..]);
        
        // Test in the other direction
        let response_message = b"Hello from the server!";
        let encrypted = server.send(response_message)?;
        let decrypted = client.receive(&encrypted)?;
        
        assert_eq!(response_message, &decrypted[..]);
        
        Ok(())
    }
}