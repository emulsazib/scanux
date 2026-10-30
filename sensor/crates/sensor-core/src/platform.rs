//! Traits each OS backend implements. Enforcement is deliberately narrow:
//! suspend/resume/terminate a process instance and block/unblock its network.

use crate::event::{ProcessKey, RawEvent};
use std::sync::mpsc::Sender;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("process {0:?} not found")]
    NotFound(ProcessKey),
    #[error("pid {pid} was reused (expected start {expected}, found {found})")]
    PidReused { pid: u32, expected: u64, found: u64 },
    #[error("operation not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("os error: {0}")]
    Os(String),
}

pub type PlatformResult<T> = Result<T, PlatformError>;

pub trait EventSource: Send {
    fn name(&self) -> &'static str;
    fn start(&mut self, tx: Sender<RawEvent>) -> PlatformResult<()>;
    fn stop(&mut self);
}

pub trait ProcessControl: Send + Sync {
    /// Current start time of `pid`, used to detect PID reuse.
    fn start_time_ms(&self, pid: u32) -> Option<u64>;
    fn suspend(&self, p: ProcessKey) -> PlatformResult<()>;
    fn resume(&self, p: ProcessKey) -> PlatformResult<()>;
    fn terminate(&self, p: ProcessKey) -> PlatformResult<()>;

    /// Rejects the call if `p.pid` now belongs to a different process instance.
    fn check_identity(&self, p: ProcessKey) -> PlatformResult<()> {
        match self.start_time_ms(p.pid) {
            None => Err(PlatformError::NotFound(p)),
            Some(found) if found != p.start_time_ms => Err(PlatformError::PidReused {
                pid: p.pid,
                expected: p.start_time_ms,
                found,
            }),
            Some(_) => Ok(()),
        }
    }
}

pub trait NetworkControl: Send + Sync {
    /// Blocks all traffic of one executable (WFP ALE app-id on Windows),
    /// leaving the rest of the machine online.
    fn block_process(&self, p: ProcessKey, image_path: &str) -> PlatformResult<()>;
    fn unblock_process(&self, p: ProcessKey, image_path: &str) -> PlatformResult<()>;
}
