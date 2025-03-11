/*!
Streaming utilities for the PQC protocol.

This module provides utilities for streaming large data in manageable
chunks, as well as receiving and reassembling streamed data.
*/

pub mod sender;
pub mod receiver;

// Re-export commonly used items
pub use sender::{StreamSender, StreamReader};
pub use receiver::StreamReceiver;

// Define a type alias for backward compatibility
/// PqcStreamSender is the main stream sender type for the protocol
pub type PqcStreamSender<'a> = StreamSender<'a>;

/// PqcStreamReceiver is the main stream receiver type for the protocol
pub type PqcStreamReceiver<'a> = StreamReceiver<'a>;