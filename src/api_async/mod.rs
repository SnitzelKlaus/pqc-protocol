/*!
Asynchronous API for the PQC protocol.

This module provides an asynchronous API for the PQC protocol,
allowing it to be used with async/await in Tokio or other async runtimes.
*/

mod client;
mod server;
mod stream;

// Re-export components for ease of use
pub use client::AsyncPqcClient;
pub use server::AsyncPqcServer;
pub use stream::{AsyncPqcSendStream, AsyncPqcReceiveStream, AsyncPqcReadExt, AsyncPqcWriteExt};