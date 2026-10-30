//! Everything that changes system state on the endpoint goes through here.
//!
//! * [`tier1`]: the only autonomous action: freeze (suspend + network block), never destroy.
//! * [`verify`]: cloud commands must be Ed25519-signed by a pinned key, bound to
//!   this device, unexpired, unreplayed, and (except Tier-1 tools) human-approved.
//! * [`executor`]: maps the closed `RemediationCommand.tool` oneof onto platform calls.

pub mod allowlist;
pub mod executor;
pub mod tier1;
pub mod verify;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
