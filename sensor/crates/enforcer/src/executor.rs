//! Executes a verified `RemediationCommand`. The match below is the complete
//! list of things the cloud can make an endpoint do.

use crate::allowlist::Allowlist;
use crate::now_ms;
use scanu_proto::v1::{
    remediation_command::Tool, CommandResult, CommandStatus, ProcessRef, RemediationCommand,
};
use sensor_core::platform::{NetworkControl, PlatformError, ProcessControl};
use sensor_core::ProcessKey;
use std::path::Path;
use std::sync::{Arc, Mutex};
use vault::{Vault, VaultError};

pub struct Executor {
    pub procs: Arc<dyn ProcessControl>,
    pub net: Arc<dyn NetworkControl>,
    pub vault: Arc<Vault>,
    pub allowlist: Arc<Mutex<Allowlist>>,
}

fn key(p: &Option<ProcessRef>) -> Result<(ProcessKey, String), String> {
    let p = p.as_ref().ok_or("MALFORMED")?;
    Ok((ProcessKey { pid: p.pid, start_time_ms: p.start_time_unix_ms }, p.image_path.clone()))
}

fn platform_reason(e: PlatformError) -> String {
    match e {
        PlatformError::PidReused { .. } => "PID_REUSED".into(),
        PlatformError::NotFound(_) => "PROCESS_NOT_FOUND".into(),
        PlatformError::Unsupported(w) => format!("UNSUPPORTED:{w}"),
        PlatformError::Os(m) => format!("OS:{m}"),
    }
}

fn vault_reason(e: VaultError) -> String {
    match e {
        VaultError::HashMismatch { .. } => "HASH_MISMATCH".into(),
        VaultError::NotFound(_) => "VAULT_ENTRY_NOT_FOUND".into(),
        VaultError::TargetExists(_) => "RESTORE_TARGET_EXISTS".into(),
        other => format!("VAULT:{other}"),
    }
}

impl Executor {
    pub fn execute(&self, cmd: &RemediationCommand) -> CommandResult {
        let mut vault_id = String::new();
        let outcome: Result<(), String> = match &cmd.tool {
            None => Err("NO_TOOL".into()),
            Some(Tool::Suspend(t)) => key(&t.process).and_then(|(k, _)| {
                self.procs.check_identity(k).and_then(|_| self.procs.suspend(k)).map_err(platform_reason)
            }),
            Some(Tool::Resume(t)) => key(&t.process).and_then(|(k, _)| {
                self.procs.check_identity(k).and_then(|_| self.procs.resume(k)).map_err(platform_reason)
            }),
            Some(Tool::Terminate(t)) => key(&t.process).and_then(|(k, _)| {
                self.procs.check_identity(k).and_then(|_| self.procs.terminate(k)).map_err(platform_reason)?;
                // Post-condition: the instance must be gone (this is what lets the cloud mark VERIFIED).
                match self.procs.start_time_ms(k.pid) {
                    Some(t) if t == k.start_time_ms => Err("POSTCONDITION:STILL_RUNNING".into()),
                    _ => Ok(()),
                }
            }),
            Some(Tool::NetBlock(t)) => key(&t.process)
                .and_then(|(k, img)| self.net.block_process(k, &img).map_err(platform_reason)),
            Some(Tool::NetUnblock(t)) => key(&t.process)
                .and_then(|(k, img)| self.net.unblock_process(k, &img).map_err(platform_reason)),
            Some(Tool::Quarantine(t)) => self
                .vault
                .quarantine(Path::new(&t.path), Some(&t.sha256), None)
                .map_err(vault_reason)
                .and_then(|e| {
                    // Post-condition: original gone and entry held in the vault.
                    let held = self.vault.get(&e.vault_id).ok().flatten().is_some();
                    vault_id = e.vault_id;
                    if Path::new(&t.path).exists() || !held {
                        Err("POSTCONDITION:NOT_QUARANTINED".into())
                    } else {
                        Ok(())
                    }
                }),
            Some(Tool::Restore(t)) => self
                .vault
                .restore(&t.vault_id)
                .map(|e| vault_id = e.vault_id)
                .map_err(vault_reason),
            // Scans are long-running and owned by the engine (engine::scan).
            Some(Tool::StartScan(_)) | Some(Tool::CancelScan(_)) => Err("HANDLED_BY_ENGINE".into()),
            Some(Tool::Allowlist(t)) => {
                if t.sha256.len() != 64 || !t.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                    Err("MALFORMED".into())
                } else {
                    self.allowlist.lock().unwrap().insert(&t.sha256).map_err(|e| format!("IO:{e}"))
                }
            }
        };
        let (status, reason) = match outcome {
            Ok(()) => (CommandStatus::Executed, String::new()),
            Err(r) => (CommandStatus::Failed, r),
        };
        tracing::info!(command_id = %cmd.command_id, ?status, %reason, "command executed");
        let now = now_ms();
        CommandResult {
            command_id: cmd.command_id.clone(),
            action_id: cmd.action_id.clone(),
            status: status as i32,
            reason,
            vault_id,
            completed_at: Some(prost_types::Timestamp { seconds: (now / 1000) as i64, nanos: ((now % 1000) * 1_000_000) as i32 }),
        }
    }
}
