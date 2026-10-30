//! On-demand Quick/Full scans on a background thread, so telemetry ingest and
//! Tier-1 are never blocked. Cheap magic-byte checks decide which files get the
//! full edge pipeline (hash → bloom → features → model → YARA). Findings become
//! alerts; the scan never deletes or quarantines on its own.

use crate::engine::{Engine, PathResolver};
use edge_ml::{Decision, EdgeEngine};
use scanu_proto::v1::{self as pb, ScanScope, ScanState};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct ScanRoots {
    /// User-writable hot spots (Downloads, Desktop, Temp, AppData, Startup, ProgramData).
    pub quick: Vec<String>,
    /// Every fixed drive root.
    pub full: Vec<String>,
    /// Lower-cased telemetry-path prefixes never scanned (the sensor's own data/vault).
    pub exclude: Vec<String>,
}

pub struct ScanJob {
    pub scan_id: String,
    pub scope: ScanScope,
    pub roots: Vec<String>,
    pub cancel: Arc<AtomicBool>,
}

const SCRIPT_EXT: &[&str] = &["ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "bat", "cmd", "scr", "sh"];
const REPORT_EVERY: Duration = Duration::from_millis(500);

fn now_ms() -> u64 {
    enforcer::now_ms()
}

fn ts(ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds: (ms / 1000) as i64, nanos: ((ms % 1000) * 1_000_000) as i32 }
}

/// Joins a telemetry-style directory path and a child name with that path's separator.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with(['\\', '/']) {
        format!("{dir}{name}")
    } else if dir.contains('\\') {
        format!("{dir}\\{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Executables (PE/ELF magic) and script files are analyzed; everything else is just counted.
fn is_candidate(path: &Path, name: &str) -> bool {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    if SCRIPT_EXT.contains(&ext.as_str()) {
        return true;
    }
    let mut magic = [0u8; 4];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic)) {
        Ok(()) => magic.starts_with(b"MZ") || magic == *b"\x7fELF",
        Err(_) => false,
    }
}

/// Starts every scan queued by `Engine::queue_scan` (called after commands are handled).
pub fn spawn_pending(engine: &Arc<Mutex<Engine>>) {
    let jobs = engine.lock().unwrap().take_pending_scans();
    for (job, edge, resolve, exclude) in jobs {
        let engine = engine.clone();
        let name = format!("scan-{}", job.scan_id);
        if let Err(e) = std::thread::Builder::new().name(name).spawn(move || run(engine, job, edge, resolve, exclude)) {
            tracing::error!(error = %e, "could not start scan thread");
        }
    }
}

/// Local trigger (desktop button while offline, simulator). Returns the scan id.
pub fn start_local(engine: &Arc<Mutex<Engine>>, scope: ScanScope) -> Result<String, &'static str> {
    let id = format!("scn_local_{}", uuid::Uuid::now_v7().simple());
    engine.lock().unwrap().queue_scan(&id, scope)?;
    spawn_pending(engine);
    Ok(id)
}

#[derive(Default)]
struct Counters {
    seen: u64,
    analyzed: u64,
    bytes: u64,
    findings: u64,
}

fn run(engine: Arc<Mutex<Engine>>, job: ScanJob, edge: Arc<EdgeEngine>, resolve: PathResolver, exclude: Vec<String>) {
    let started = now_ms();
    let mut c = Counters::default();
    let mut last = Instant::now();
    let mut current = String::new();
    let mut stack: Vec<String> = job.roots.iter().rev().cloned().collect();
    let report = |c: &Counters, state: ScanState, current: &str, error: &str| pb::ScanProgress {
        scan_id: job.scan_id.clone(),
        state: state as i32,
        files_seen: c.seen,
        files_analyzed: c.analyzed,
        bytes_analyzed: c.bytes,
        findings: c.findings,
        current_path: current.to_string(),
        started_at: Some(ts(started)),
        finished_at: (state != ScanState::Running).then(|| ts(now_ms())),
        error: error.to_string(),
        scope: job.scope as i32,
    };
    engine.lock().unwrap().scan_progress(report(&c, ScanState::Running, "", ""));
    tracing::info!(scan_id = %job.scan_id, scope = ?job.scope, roots = job.roots.len(), "scan started");

    let mut state = ScanState::Completed;
    'walk: while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(resolve(&dir)) else { continue };
        for entry in entries.flatten() {
            if job.cancel.load(Ordering::Relaxed) {
                state = ScanState::Cancelled;
                break 'walk;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let tele = join(&dir, &name);
            if exclude.iter().any(|e| tele.to_lowercase().starts_with(e)) {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue; // never follow links (loops, reparse points)
            }
            if ft.is_dir() {
                stack.push(tele);
                continue;
            }
            c.seen += 1;
            let real = entry.path();
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if len < 64 || len as usize > edge.max_parse_bytes || !is_candidate(&real, &name) {
                continue;
            }
            current = tele.clone();
            if let Ok(v) = edge.analyze_file(&real) {
                c.analyzed += 1;
                c.bytes += len;
                if matches!(v.decision, Decision::Malicious | Decision::Suspicious) {
                    c.findings += 1;
                    engine.lock().unwrap().scan_finding(&job.scan_id, &tele, &v);
                }
            }
            if last.elapsed() >= REPORT_EVERY {
                engine.lock().unwrap().scan_progress(report(&c, ScanState::Running, &current, ""));
                last = Instant::now();
            }
            std::thread::yield_now(); // stay polite to foreground work
        }
    }
    engine.lock().unwrap().scan_progress(report(&c, state, &current, ""));
}
