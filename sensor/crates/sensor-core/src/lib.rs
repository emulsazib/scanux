//! Platform-neutral building blocks for the Scanu endpoint sensor.
//!
//! Platform crates (`sensor-win`, `sensor-linux`, `sensor-macos`) turn OS
//! telemetry into [`event::RawEvent`]s and implement the control traits in
//! [`platform`]. Everything else (normalization, spooling, detection) lives
//! here so it can be tested on any host.

pub mod canary;
pub mod detect;
pub mod event;
pub mod mock;
pub mod ocsf;
pub mod platform;
pub mod privacy;
pub mod spool;

pub use event::{FileOp, ProcessKey, RawEvent};
