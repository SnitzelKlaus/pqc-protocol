/*!
Streaming functionality for the PQC protocol.

This module provides core streaming components that can be used
by both synchronous and asynchronous APIs.
*/

// Stream sender functionality
pub mod sender;

// Stream receiver functionality
pub mod receiver;

// Re-export main components
pub use sender::PqcStreamSender;
pub use receiver::PqcStreamReceiver;