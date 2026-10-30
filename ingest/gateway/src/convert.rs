//! Proto → JSON for the Python consumers. Enum values become stable lowercase names.

use scanu_proto::v1::{alert::Reason, Alert, CommandResult, CommandStatus, FreezeState, ScanProgress, ScanState, Severity};
use serde_json::{json, Value};

fn ts_ms(t: &Option<prost_types::Timestamp>) -> i64 {
    t.as_ref().map(|t| t.seconds * 1000 + (t.nanos / 1_000_000) as i64).unwrap_or(0)
}

pub fn alert_json(a: &Alert, tenant_id: &str) -> Value {
    let severity = match Severity::try_from(a.severity).unwrap_or(Severity::Unspecified) {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        Severity::Unspecified => "unspecified",
    };
    let tier1 = match FreezeState::try_from(a.tier1).unwrap_or(FreezeState::Unspecified) {
        FreezeState::Suspended => "suspended",
        FreezeState::NetBlocked => "net_blocked",
        FreezeState::SuspendedAndNetBlocked => "suspended_and_net_blocked",
        _ => "none",
    };
    let reason = match &a.reason {
        Some(Reason::Bloom(b)) => json!({ "kind": "bloom", "sha256": b.sha256, "feed": b.feed }),
        Some(Reason::Ml(m)) => json!({ "kind": "ml", "model_version": m.model_version, "score": m.score, "top_features": m.top_features }),
        Some(Reason::Canary(c)) => json!({ "kind": "canary", "canary_id": c.canary_id, "operation": c.operation, "frozen_us": c.frozen_us }),
        Some(Reason::Yara(y)) => json!({ "kind": "yara", "rules": y.rules }),
        Some(Reason::Heuristic(h)) => json!({ "kind": "heuristic", "name": h.name, "score": h.score, "detail": h.detail }),
        None => json!({ "kind": "unknown" }),
    };
    json!({
        "alert_id": a.alert_id,
        "tenant_id": tenant_id,
        "device_id": a.device_id,
        "event_ids": a.event_ids,
        "severity": severity,
        "confidence": a.confidence,
        "raised_at_ms": ts_ms(&a.raised_at),
        "reason": reason,
        "tier1": tier1,
        "process": a.process.as_ref().map(|p| json!({
            "pid": p.pid, "start_time_unix_ms": p.start_time_unix_ms,
            "image_path": p.image_path, "sha256": p.sha256, "parent_pid": p.parent_pid,
        })),
        "file_path": a.file_path,
        "file_sha256": a.file_sha256,
        "scan_id": a.scan_id,
    })
}

pub fn result_json(r: &CommandResult, tenant_id: &str, device_id: &str) -> Value {
    let status = match CommandStatus::try_from(r.status).unwrap_or(CommandStatus::Unspecified) {
        CommandStatus::Executed => "executed",
        CommandStatus::Rejected => "rejected",
        CommandStatus::Failed => "failed",
        CommandStatus::Unspecified => "unspecified",
    };
    json!({
        "tenant_id": tenant_id,
        "device_id": device_id,
        "command_id": r.command_id,
        "action_id": r.action_id,
        "status": status,
        "reason": r.reason,
        "vault_id": r.vault_id,
        "completed_at_ms": ts_ms(&r.completed_at),
    })
}

pub fn scan_json(p: &ScanProgress, tenant_id: &str, device_id: &str) -> Value {
    let state = match ScanState::try_from(p.state).unwrap_or(ScanState::Unspecified) {
        ScanState::Running => "running",
        ScanState::Completed => "completed",
        ScanState::Cancelled => "cancelled",
        ScanState::Failed => "failed",
        ScanState::Unspecified => "unspecified",
    };
    json!({
        "tenant_id": tenant_id,
        "device_id": device_id,
        "scan_id": p.scan_id,
        "state": state,
        "files_seen": p.files_seen,
        "files_analyzed": p.files_analyzed,
        "bytes_analyzed": p.bytes_analyzed,
        "findings": p.findings,
        "current_path": p.current_path,
        "started_at_ms": ts_ms(&p.started_at),
        "finished_at_ms": ts_ms(&p.finished_at),
        "error": p.error,
        "scope": if p.scope == scanu_proto::v1::ScanScope::Full as i32 { "full" } else { "quick" },
    })
}
