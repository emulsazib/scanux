//! Tier-1: immediate, local, offline-capable freeze for high-confidence
//! destructive behaviour. Suspends threads and blocks the process's network.
//! It never terminates or deletes; that needs a human (Tier-2/3).

use scanu_proto::v1::FreezeState;
use sensor_core::platform::{NetworkControl, ProcessControl};
use sensor_core::ProcessKey;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum Trigger {
    Canary { canary_id: String },
    BloomHit { sha256: String },
    Ml { score: f32, yara_matches: usize },
    MassModify { files_in_window: usize },
}

pub struct Tier1Policy {
    /// ML alone is never enough: it also needs a YARA corroboration.
    pub ml_threshold: f32,
    pub mass_modify_threshold: usize,
}

impl Default for Tier1Policy {
    fn default() -> Self {
        Self { ml_threshold: 0.98, mass_modify_threshold: 50 }
    }
}

#[derive(Debug, Clone)]
pub struct FreezeOutcome {
    pub state: FreezeState,
    pub suspend_error: Option<String>,
    pub net_error: Option<String>,
    pub elapsed_us: u64,
}

impl Tier1Policy {
    pub fn should_freeze(&self, t: &Trigger) -> bool {
        match t {
            Trigger::Canary { .. } | Trigger::BloomHit { .. } => true,
            Trigger::Ml { score, yara_matches } => *score >= self.ml_threshold && *yara_matches > 0,
            Trigger::MassModify { files_in_window } => *files_in_window >= self.mass_modify_threshold,
        }
    }

    /// Suspend first (stops further damage), then block network.
    pub fn freeze(
        &self,
        procs: &dyn ProcessControl,
        net: &dyn NetworkControl,
        p: ProcessKey,
        image_path: &str,
    ) -> FreezeOutcome {
        let t0 = Instant::now();
        let suspend_error = procs.suspend(p).err().map(|e| e.to_string());
        let net_error = net.block_process(p, image_path).err().map(|e| e.to_string());
        let state = match (suspend_error.is_none(), net_error.is_none()) {
            (true, true) => FreezeState::SuspendedAndNetBlocked,
            (true, false) => FreezeState::Suspended,
            (false, true) => FreezeState::NetBlocked,
            (false, false) => FreezeState::None,
        };
        FreezeOutcome { state, suspend_error, net_error, elapsed_us: t0.elapsed().as_micros() as u64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_requires_corroboration() {
        let p = Tier1Policy::default();
        assert!(!p.should_freeze(&Trigger::Ml { score: 0.999, yara_matches: 0 }));
        assert!(!p.should_freeze(&Trigger::Ml { score: 0.90, yara_matches: 3 }));
        assert!(p.should_freeze(&Trigger::Ml { score: 0.985, yara_matches: 1 }));
        assert!(p.should_freeze(&Trigger::Canary { canary_id: "c".into() }));
        assert!(!p.should_freeze(&Trigger::MassModify { files_in_window: 10 }));
    }
}
