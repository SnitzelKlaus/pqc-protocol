/*!
Synchronous API for the PQC protocol.

This module provides a synchronous API for the PQC protocol,
organized into client, server, and stream components.
*/

mod client;
mod server;
mod stream;

// Re-export components for ease of use
pub use client::PqcClient;
pub use server::PqcServer;
pub use stream::{PqcSyncStreamSender, PqcSyncStreamReceiver, PqcReadExt, PqcWriteExt};