/*!
Protocol builder for the PQC protocol.

This module provides a builder pattern for creating protocol instances
with specific configurations.
*/

use crate::core::{
    error::Result,
    crypto::config::{CryptoConfig, KeyExchangeAlgorithm, SignatureAlgorithm, SymmetricAlgorithm},
    session::state::Role,
};

// Import the client and server implementations
use crate::protocol::client::sync_client::PqcClient;
use crate::protocol::server::sync_server::PqcServer;

#[cfg(feature = "async")]
use crate::protocol::client::async_client::AsyncPqcClient;
#[cfg(feature = "async")]
use crate::protocol::server::async_server::AsyncPqcServer;

/// Builder for PQC protocol instances
pub struct PqcProtocolBuilder {
    /// Cryptographic configuration
    config: CryptoConfig,
    
    /// Role (client or server)
    role: Role,
    
    /// Memory security setting
    secure_memory: bool,
}

impl PqcProtocolBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: CryptoConfig::default(),
            role: Role::Client,
            secure_memory: true,
        }
    }
    
    /// Set the role (client or server)
    pub fn with_role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }
    
    /// Set as client
    pub fn as_client(mut self) -> Self {
        self.role = Role::Client;
        self
    }
    
    /// Set as server
    pub fn as_server(mut self) -> Self {
        self.role = Role::Server;
        self
    }
    
    /// Use a specific key exchange algorithm
    pub fn with_key_exchange(mut self, algorithm: KeyExchangeAlgorithm) -> Self {
        self.config.key_exchange = algorithm;
        self
    }
    
    /// Use a specific signature algorithm
    pub fn with_signature(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.config.signature = algorithm;
        self
    }
    
    /// Use a specific symmetric algorithm
    pub fn with_symmetric(mut self, algorithm: SymmetricAlgorithm) -> Self {
        self.config.symmetric = algorithm;
        self
    }
    
    /// Use a preset configuration for lightweight environments
    pub fn lightweight(mut self) -> Self {
        self.config = CryptoConfig::lightweight();
        self
    }
    
    /// Use a preset configuration for high security
    pub fn high_security(mut self) -> Self {
        self.config = CryptoConfig::high_security();
        self
    }
    
    /// Use a preset configuration optimized for hardware acceleration
    pub fn hardware_optimized(mut self) -> Self {
        self.config = CryptoConfig::hardware_optimized();
        self
    }
    
    /// Enable secure memory
    pub fn with_secure_memory(mut self, secure: bool) -> Self {
        self.secure_memory = secure;
        self
    }
    
    /// Build a synchronous client
    pub fn build_client(self) -> Result<PqcClient> {
        let mut client = PqcClient::with_config(self.config.clone())?;
        client.set_role(Role::Client);
        if !self.secure_memory {
            client.disable_secure_memory()?;
        }
        Ok(client)
    }
    
    /// Build a synchronous server
    pub fn build_server(self) -> Result<PqcServer> {
        let mut server = PqcServer::with_config(self.config.clone())?;
        server.set_role(Role::Server);
        if !self.secure_memory {
            server.disable_secure_memory()?;
        }
        Ok(server)
    }
    
    /// Build an asynchronous client (requires "async" feature)
    #[cfg(feature = "async")]
    pub async fn build_async_client(self) -> Result<AsyncPqcClient> {
        let mut client = AsyncPqcClient::with_config(self.config.clone()).await?;
        if !self.secure_memory {
            client.disable_secure_memory().await?;
        }
        Ok(client)
    }
    
    /// Build an asynchronous server (requires "async" feature)
    #[cfg(feature = "async")]
    pub async fn build_async_server(self) -> Result<AsyncPqcServer> {
        let mut server = AsyncPqcServer::with_config(self.config.clone()).await?;
        if !self.secure_memory {
            server.disable_secure_memory().await?;
        }
        Ok(server)
    }
}

impl Default for PqcProtocolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience functions

/// Create a client with default settings
pub fn client() -> Result<PqcClient> {
    PqcProtocolBuilder::new().build_client()
}

/// Create a server with default settings
pub fn server() -> Result<PqcServer> {
    PqcProtocolBuilder::new().as_server().build_server()
}

#[cfg(feature = "async")]
/// Create an async client with default settings
pub async fn async_client() -> Result<AsyncPqcClient> {
    PqcProtocolBuilder::new().build_async_client().await
}

#[cfg(feature = "async")]
/// Create an async server with default settings
pub async fn async_server() -> Result<AsyncPqcServer> {
    PqcProtocolBuilder::new().as_server().build_async_server().await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_builder_defaults() -> Result<()> {
        let client = PqcProtocolBuilder::new().build_client()?;
        assert_eq!(client.session().state(), crate::core::session::state::SessionState::New);
        
        let server = PqcProtocolBuilder::new().as_server().build_server()?;
        assert_eq!(server.role(), Role::Server);
        
        Ok(())
    }
    
    #[test]
    fn test_builder_configuration() -> Result<()> {
        let high_sec_client = PqcProtocolBuilder::new()
            .high_security()
            .build_client()?;
        
        let light_client = PqcProtocolBuilder::new()
            .lightweight()
            .build_client()?;
        
        let custom_client = PqcProtocolBuilder::new()
            .with_key_exchange(KeyExchangeAlgorithm::Kyber768)
            .with_signature(SignatureAlgorithm::Dilithium3)
            .with_symmetric(SymmetricAlgorithm::ChaCha20Poly1305)
            .build_client()?;
        
        assert_ne!(
            high_sec_client.session().crypto_config().key_exchange,
            light_client.session().crypto_config().key_exchange
        );
        
        Ok(())
    }
    
    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_async_builder() -> Result<()> {
        let client = PqcProtocolBuilder::new()
            .build_async_client()
            .await?;
        
        let server = PqcProtocolBuilder::new()
            .as_server()
            .build_async_server()
            .await?;
        
        assert_eq!(client.state().await?, crate::core::session::state::SessionState::New);
        
        Ok(())
    }
}