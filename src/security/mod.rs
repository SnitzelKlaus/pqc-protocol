//! Security utilities for the PQC protocol.

mod constant_time;
mod rotation;

pub use constant_time::{constant_time_eq, constant_time_select, constant_time_increment};
pub use rotation::{
    KeyRotationManager, KeyRotationParams, SessionStats, PqcSessionKeyRotation,
    handle_auto_rotation
};