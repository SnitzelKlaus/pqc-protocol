/*!
Protocol builder for the PQC protocol.

This module provides a builder pattern for creating protocol instances
with specific configurations, including cryptographic algorithms and
memory security options.
*/

use crate::core::{
    error::Result,
    crypto::config::{CryptoConfig, KeyExchangeAlgorithm, SignatureAlgorithm, SymmetricAlgorithm},
    session::state::Role,
    memory::{MemorySecurity, MemoryConfig},
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
    
    /// Memory configuration
    memory_config: MemoryConfig,
}

impl PqcProtocolBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: CryptoConfig::default(),
            role: Role::Client,
            memory_config: MemoryConfig::default(),
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
        self.memory_config = MemoryConfig::embedded();
        self
    }
    
    /// Use a preset configuration for high security
    pub fn high_security(mut self) -> Self {
        self.config = CryptoConfig::high_security();
        self.memory_config = MemoryConfig::standard()
            .with_security_level(MemorySecurity::Maximum);
        self
    }
    
    /// Use a preset configuration optimized for hardware acceleration
    pub fn hardware_optimized(mut self) -> Self {
        self.config = CryptoConfig::hardware_optimized();
        self
    }
    
    /// Configure for WebAssembly environment
    pub fn for_wasm(mut self) -> Self {
        self.memory_config = MemoryConfig::wasm();
        self
    }
    
    /// Configure for embedded environment
    pub fn for_embedded(mut self) -> Self {
        self.memory_config = MemoryConfig::embedded();
        self.config = CryptoConfig::lightweight();
        self
    }
    
    /// Configure for mobile environment
    pub fn for_mobile(mut self) -> Self {
        self.memory_config = MemoryConfig::mobile();
        self
    }
    
    /// Set a custom memory configuration
    pub fn with_memory_config(mut self, memory_config: MemoryConfig) -> Self {
        self.memory_config = memory_config;
        self
    }
    
    /// Set memory security level
    pub fn with_memory_security(mut self, level: MemorySecurity) -> Self {
        self.memory_config = self.memory_config.with_security_level(level);
        self
    }
    
    /// Enable or disable memory locking
    pub fn with_memory_locking(mut self, enable: bool) -> Self {
        self.memory_config = self.memory_config.with_memory_locking(enable);
        self
    }
    
    /// Enable or disable canary protection
    pub fn with_canary_protection(mut self, enable: bool) -> Self {
        self.memory_config = self.memory_config.with_canary(enable);
        self
    }
    
    /// Build a synchronous client
    pub fn build_client(self) -> Result<PqcClient> {
        let mut client = PqcClient::with_config(self.config.clone())?;
        client.set_role(Role::Client);
        
        // Apply memory configuration
        let mut memory_manager = client.session_mut().memory_manager_mut();
        self.memory_config.apply_to_manager(memory_manager);
        
        Ok(client)
    }
    
    /// Build a synchronous server
    pub fn build_server(self) -> Result<PqcServer> {
        let mut server = PqcServer::with_config(self.config.clone())?;
        server.set_role(Role::Server);
        
        // Apply memory configuration
        let mut memory_manager = server.session_mut().memory_manager_mut();
        self.memory_config.apply_to_manager(memory_manager);
        
        Ok(server)
    }
    
    /// Build an asynchronous client (requires "async" feature)
    #[cfg(feature = "async")]
    pub async fn build_async_client(self) -> Result<AsyncPqcClient> {
        let client = AsyncPqcClient::with_config(self.config.clone()).await?;
        
        // Apply memory configuration
        client.with_session(|session| async move {
            self.memory_config.apply_to_manager(session.memory_manager_mut());
            Ok(())
        }).await?;
        
        Ok(client)
    }
    
    /// Build an asynchronous server (requires "async" feature)
    #[cfg(feature = "async")]
    pub async fn build_async_server(self) -> Result<AsyncPqcServer> {
        let server = AsyncPqcServer::with_config(self.config.clone()).await?;
        
        // Apply memory configuration
        server.with_session(|session| async move {
            self.memory_config.apply_to_manager(session.memory_manager_mut());
            Ok(())
        }).await?;
        
        Ok(server)
    }
}

impl Default for PqcProtocolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Convenience functions with platform detection

/// Create a client with automatically detected platform settings
pub fn client_for_platform() -> Result<PqcClient> {
    let config = crate::memory::for_current_platform();
    
    PqcProtocolBuilder::new()
        .with_memory_config(config)
        .build_client()
}

/// Create a server with automatically detected platform settings
pub fn server_for_platform() -> Result<PqcServer> {
    let config = crate::memory::for_current_platform();
    
    PqcProtocolBuilder::new()
        .as_server()
        .with_memory_config(config)
        .build_server()
}

#[cfg(feature = "async")]
/// Create an async client with automatically detected platform settings
pub async fn async_client_for_platform() -> Result<AsyncPqcClient> {
    let config = crate::memory::for_current_platform();
    
    PqcProtocolBuilder::new()
        .with_memory_config(config)
        .build_async_client()
        .await
}

#[cfg(feature = "async")]
/// Create an async server with automatically detected platform settings
pub async fn async_server_for_platform() -> Result<AsyncPqcServer> {
    let config = crate::memory::for_current_platform();
    
    PqcProtocolBuilder::new()
        .as_server()
        .with_memory_config(config)
        .build_async_server()
        .await
}

// Original convenience functions

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
    
    #[test]
    fn test_memory_configuration() -> Result<()> {
        // Test standard memory configuration
        let standard_client = PqcProtocolBuilder::new().build_client()?;
        assert!(standard_client.session().memory_manager().is_memory_locking_enabled());
        assert!(standard_client.session().memory_manager().is_canary_protection_enabled());
        
        // Test embedded memory configuration
        let embedded_client = PqcProtocolBuilder::new()
            .for_embedded()
            .build_client()?;
        assert!(!embedded_client.session().memory_manager().is_memory_locking_enabled());
        assert!(!embedded_client.session().memory_manager().is_canary_protection_enabled());
        
        // Test WASM memory configuration
        let wasm_client = PqcProtocolBuilder::new()
            .for_wasm()
            .build_client()?;
        assert!(!wasm_client.session().memory_manager().is_memory_locking_enabled());
        assert!(wasm_client.session().memory_manager().is_canary_protection_enabled());
        
        // Test custom memory configuration
        let custom_client = PqcProtocolBuilder::new()
            .with_memory_security(MemorySecurity::Enhanced)
            .with_memory_locking(false)
            .with_canary_protection(true)
            .build_client()?;
        assert!(!custom_client.session().memory_manager().is_memory_locking_enabled());
        assert!(custom_client.session().memory_manager().is_canary_protection_enabled());
        assert_eq!(custom_client.session().memory_security_level(), MemorySecurity::Enhanced);
        
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
    
    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_async_memory_config() -> Result<()> {
        // This is a bit tricker to test with the async API
        let client = PqcProtocolBuilder::new()
            .with_memory_security(MemorySecurity::Maximum)
            .build_async_client()
            .await?;
        
        // Verify the memory security level was set
        client.with_session(|session| async move {
            assert_eq!(session.memory_security_level(), MemorySecurity::Maximum);
            Ok(())
        }).await?;
        
        Ok(())
    }
}