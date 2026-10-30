//! Linux backend: not implemented in the MVP. Planned mapping:
//!
//! | Need | Mechanism |
//! |---|---|
//! | Blocking file intercept, pre-exec | fanotify `FAN_OPEN_EXEC_PERM` / `FAN_OPEN_PERM`, or eBPF LSM `bprm_check_security` / `file_open` (Aya) |
//! | Process / network telemetry | eBPF tracepoints `sched_process_exec`, `inet_sock_set_state` (PID-bound) |
//! | Per-process network block | cgroup v2 + eBPF `cgroup/connect4,6` programs |
//! | Logs | auditd netlink, journald |
//! | Anti-tamper | `kernel.lockdown=integrity`, LSM hooks on ptrace/kill of the sensor |

use sensor_core::platform::{NetworkControl, PlatformError, PlatformResult, ProcessControl};
use sensor_core::ProcessKey;

pub struct Unsupported;

impl ProcessControl for Unsupported {
    fn start_time_ms(&self, _pid: u32) -> Option<u64> {
        None
    }
    fn suspend(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("linux backend is post-MVP"))
    }
    fn resume(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("linux backend is post-MVP"))
    }
    fn terminate(&self, _p: ProcessKey) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("linux backend is post-MVP"))
    }
}

impl NetworkControl for Unsupported {
    fn block_process(&self, _p: ProcessKey, _image: &str) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("linux backend is post-MVP"))
    }
    fn unblock_process(&self, _p: ProcessKey, _image: &str) -> PlatformResult<()> {
        Err(PlatformError::Unsupported("linux backend is post-MVP"))
    }
}
