//! In-memory platform used by tests and `sensor-sim`. Records every control
//! action so scenarios can assert on what the sensor did.

use crate::event::ProcessKey;
use crate::platform::{NetworkControl, PlatformError, PlatformResult, ProcessControl};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Running,
    Suspended,
    Terminated,
}

#[derive(Default)]
pub struct MockPlatform {
    procs: Mutex<HashMap<u32, (u64, ProcState)>>,
    blocked: Mutex<HashSet<String>>,
    log: Mutex<Vec<String>>,
}

impl MockPlatform {
    pub fn spawn(&self, p: ProcessKey) {
        self.procs.lock().unwrap().insert(p.pid, (p.start_time_ms, ProcState::Running));
    }

    pub fn state(&self, p: ProcessKey) -> Option<ProcState> {
        self.procs.lock().unwrap().get(&p.pid).filter(|(t, _)| *t == p.start_time_ms).map(|x| x.1)
    }

    pub fn is_blocked(&self, image_path: &str) -> bool {
        self.blocked.lock().unwrap().contains(&image_path.to_lowercase())
    }

    pub fn actions(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn set(&self, p: ProcessKey, s: ProcState, verb: &str) -> PlatformResult<()> {
        self.check_identity(p)?;
        self.procs.lock().unwrap().insert(p.pid, (p.start_time_ms, s));
        self.log.lock().unwrap().push(format!("{verb} pid={}", p.pid));
        Ok(())
    }
}

impl ProcessControl for MockPlatform {
    fn start_time_ms(&self, pid: u32) -> Option<u64> {
        self.procs.lock().unwrap().get(&pid).filter(|(_, s)| *s != ProcState::Terminated).map(|x| x.0)
    }
    fn suspend(&self, p: ProcessKey) -> PlatformResult<()> {
        self.set(p, ProcState::Suspended, "suspend")
    }
    fn resume(&self, p: ProcessKey) -> PlatformResult<()> {
        self.set(p, ProcState::Running, "resume")
    }
    fn terminate(&self, p: ProcessKey) -> PlatformResult<()> {
        self.set(p, ProcState::Terminated, "terminate")
    }
}

impl NetworkControl for MockPlatform {
    fn block_process(&self, p: ProcessKey, image_path: &str) -> PlatformResult<()> {
        if image_path.is_empty() {
            return Err(PlatformError::Os("no image path".into()));
        }
        self.blocked.lock().unwrap().insert(image_path.to_lowercase());
        self.log.lock().unwrap().push(format!("net_block pid={}", p.pid));
        Ok(())
    }
    fn unblock_process(&self, p: ProcessKey, image_path: &str) -> PlatformResult<()> {
        self.blocked.lock().unwrap().remove(&image_path.to_lowercase());
        self.log.lock().unwrap().push(format!("net_unblock pid={}", p.pid));
        Ok(())
    }
}
