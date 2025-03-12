/*!
Session state management for the PQC protocol.

This module defines session states and the state machine for session progression.
*/

use std::fmt;

/// Session state for tracking connection progress
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionState {
    /// Session is new, no keys exchanged
    New,
    /// Key exchange initiated (client side)
    KeyExchangeInitiated,
    /// Key exchange completed (after client processed server response)
    KeyExchangeCompleted,
    /// Authentication initiated (verification keys exchanged)
    AuthenticationInitiated,
    /// Authentication completed (verification keys verified)
    AuthenticationCompleted,
    /// Session established and ready for data transfer
    Established,
    /// Session closed
    Closed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::New => write!(f, "New"),
            SessionState::KeyExchangeInitiated => write!(f, "KeyExchangeInitiated"),
            SessionState::KeyExchangeCompleted => write!(f, "KeyExchangeCompleted"),
            SessionState::AuthenticationInitiated => write!(f, "AuthenticationInitiated"),
            SessionState::AuthenticationCompleted => write!(f, "AuthenticationCompleted"),
            SessionState::Established => write!(f, "Established"),
            SessionState::Closed => write!(f, "Closed"),
        }
    }
}

/// Endpoint role in the session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client role (initiates connection)
    Client,
    /// Server role (accepts connection)
    Server,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Client => write!(f, "Client"),
            Role::Server => write!(f, "Server"),
        }
    }
}

/// Session state manager
///
/// Handles state transitions and validation of operations
/// based on the current session state.
#[derive(Debug, Clone, Copy)]
pub struct StateManager {
    /// Current state of the session
    state: SessionState,
    /// Role of this endpoint
    role: Role,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(role: Role) -> Self {
        Self {
            state: SessionState::New,
            role,
        }
    }
    
    /// Get the current state
    pub fn state(&self) -> SessionState {
        self.state
    }
    
    /// Get the role
    pub fn role(&self) -> Role {
        self.role
    }
    
    /// Set a new role
    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }
    
    /// Check if the session is in the given state
    pub fn is_state(&self, state: SessionState) -> bool {
        self.state == state
    }
    
    /// Check if the session is in any of the given states
    pub fn is_in_states(&self, states: &[SessionState]) -> bool {
        states.contains(&self.state)
    }
    
    /// Check if the current state is at least the given state
    /// (based on the natural progression of states)
    pub fn is_at_least(&self, state: SessionState) -> bool {
        self.state >= state
    }
    
    /// Check if a key exchange initialization is allowed
    pub fn can_init_key_exchange(&self) -> bool {
        self.role == Role::Client && self.state == SessionState::New
    }
    
    /// Check if accepting a key exchange is allowed
    pub fn can_accept_key_exchange(&self) -> bool {
        self.role == Role::Server && self.state == SessionState::New
    }
    
    /// Check if processing a key exchange response is allowed
    pub fn can_process_key_exchange(&self) -> bool {
        self.role == Role::Client && self.state == SessionState::KeyExchangeInitiated
    }
    
    /// Check if setting the verification key is allowed
    pub fn can_set_verification_key(&self) -> bool {
        self.state >= SessionState::KeyExchangeCompleted
    }
    
    /// Check if completing authentication is allowed
    pub fn can_complete_authentication(&self) -> bool {
        self.state == SessionState::AuthenticationInitiated
    }
    
    /// Check if data transfer is allowed
    pub fn can_transfer_data(&self) -> bool {
        self.state == SessionState::Established
    }
    
    /// Transition to the key exchange initiated state
    pub fn transition_to_key_exchange_initiated(&mut self) {
        if self.can_init_key_exchange() {
            self.state = SessionState::KeyExchangeInitiated;
        }
    }
    
    /// Transition to the key exchange completed state
    pub fn transition_to_key_exchange_completed(&mut self) {
        if self.state == SessionState::KeyExchangeInitiated || 
           self.state == SessionState::New {
            self.state = SessionState::KeyExchangeCompleted;
        }
    }
    
    /// Transition to the authentication initiated state
    pub fn transition_to_authentication_initiated(&mut self) {
        if self.state == SessionState::KeyExchangeCompleted {
            self.state = SessionState::AuthenticationInitiated;
        }
    }
    
    /// Transition to the established state
    pub fn transition_to_established(&mut self) {
        if self.state == SessionState::AuthenticationInitiated {
            self.state = SessionState::Established;
        }
    }
    
    /// Transition to the closed state
    pub fn transition_to_closed(&mut self) {
        self.state = SessionState::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_state_transitions() {
        let mut manager = StateManager::new(Role::Client);
        
        assert_eq!(manager.state(), SessionState::New);
        assert!(manager.can_init_key_exchange());
        
        manager.transition_to_key_exchange_initiated();
        assert_eq!(manager.state(), SessionState::KeyExchangeInitiated);
        assert!(manager.can_process_key_exchange());
        
        manager.transition_to_key_exchange_completed();
        assert_eq!(manager.state(), SessionState::KeyExchangeCompleted);
        assert!(manager.can_set_verification_key());
        
        manager.transition_to_authentication_initiated();
        assert_eq!(manager.state(), SessionState::AuthenticationInitiated);
        assert!(manager.can_complete_authentication());
        
        manager.transition_to_established();
        assert_eq!(manager.state(), SessionState::Established);
        assert!(manager.can_transfer_data());
        
        manager.transition_to_closed();
        assert_eq!(manager.state(), SessionState::Closed);
    }
    
    #[test]
    fn test_invalid_transitions() {
        let mut manager = StateManager::new(Role::Client);
        
        // Try transitioning to established without going through other states
        manager.transition_to_established();
        assert_eq!(manager.state(), SessionState::New);
        
        // Try transitioning to authentication initiated without key exchange
        manager.transition_to_authentication_initiated();
        assert_eq!(manager.state(), SessionState::New);
        
        // Set appropriate state then try to skip ahead
        manager.transition_to_key_exchange_initiated();
        manager.transition_to_established();
        assert_eq!(manager.state(), SessionState::KeyExchangeInitiated);
    }
    
    #[test]
    fn test_role_permissions() {
        let client = StateManager::new(Role::Client);
        let server = StateManager::new(Role::Server);
        
        assert!(client.can_init_key_exchange());
        assert!(!server.can_init_key_exchange());
        
        assert!(!client.can_accept_key_exchange());
        assert!(server.can_accept_key_exchange());
    }
}