//! macOS backend: not implemented in the MVP. Planned mapping:
//!
//! | Need | Mechanism |
//! |---|---|
//! | Blocking file intercept, pre-exec | EndpointSecurity `ES_EVENT_TYPE_AUTH_OPEN` / `AUTH_EXEC` (needs the com.apple.developer.endpoint-security.client entitlement) |
//! | Process / network telemetry | ES `NOTIFY_EXEC/FORK/EXIT`, NetworkExtension flow metadata |
//! | Per-process network block | NEFilterDataProvider verdicts by audit token |
//! | Logs | Unified Logging (OSLogStore / `log stream`) |
//! | Anti-tamper | System Extension + SIP; ES `AUTH_SIGNAL` to deny kills of the sensor |

use sensor_core::platform::{NetworkControl, PlatformError, PlatformResult, ProcessControl};
use sensor_core::ProcessKey;

pub struct Unsupported;

impl ProcessControl for Unsupported {
    fn start_time_ms(&self, _pid: u32) -> Option<u64> {
        None
    }
    fn suspend(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("macos backend is post-MVP"))
    }
    fn resume(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("macos backend is post-MVP"))
    }
    fn terminate(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("macos backend is post-MVP"))
    }
}

impl NetworkControl for Unsupported {
    fn block_process(&self, _p: ProcessKey, _image: &str) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("macos backend is post-MVP"))
    }
    fn unblock_process(&self, _p: ProcessKey, _image: &str) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("macos backend is post-MVP"))
    }
}
