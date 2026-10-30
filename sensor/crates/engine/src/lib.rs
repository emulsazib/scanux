//! The sensor runtime shared by `sensor-svc` (Windows service) and
//! `sensor-sim` (cross-platform simulator). Platform crates provide events and
//! the [`sensor_core::platform`] controls; everything else happens here.

pub mod engine;
pub mod scan;

pub mod uplink;

pub use engine::{Engine, EngineConfig, ExecDecision, LocalNotice};
