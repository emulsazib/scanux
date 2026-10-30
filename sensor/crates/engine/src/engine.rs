use edge_ml::{Decision, EdgeEngine, Verdict};
use enforcer::allowlist::Allowlist;
use enforcer::executor::Executor;
use enforcer::tier1::{FreezeOutcome, Tier1Policy, Trigger};
use enforcer::verify::{CommandVerifier, NonceStore};
use prost::Message;
use scanu_proto::v1::{
    self as pb, alert::Reason, remediation_command::Tool, CommandResult, CommandStatus, EventBatch,
    EventEnvelope, FreezeState, Priority, ProcessRef, Severity, SignedCommand,
};
use sensor_core::canary::{self, CanarySet, CanarySpec};
use sensor_core::detect::{dga_score, dns_tunnel_score, BeaconTracker, MassModifyTracker};
use sensor_core::ocsf::{DeviceInfo, Normalizer};
use sensor_core::platform::{NetworkControl, ProcessControl};
use sensor_core::privacy::Pseudonymizer;
use sensor_core::spool::Spool;
use sensor_core::{FileOp, ProcessKey, RawEvent};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use vault::Vault;

use crate::scan::{ScanJob, ScanRoots};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Maps a path as seen in telemetry to a real filesystem path. Identity on a
/// real endpoint; the simulator maps `C:\Users\...` into a sandbox directory.
pub type PathResolver = Arc<dyn Fn(&str) -> PathBuf + Send + Sync>;

pub struct EngineConfig {
    pub device_id: String,
    pub os_name: String,
    pub data_dir: PathBuf,
    pub spool_cap_bytes: u64,
    pub pseudonym_salt: [u8; 16],
    /// Pinned command-signing keys by key_id (current + next).
    pub signing_keys: HashMap<String, ed25519_dalek::VerifyingKey>,
    pub vault_key: Box<dyn vault::KeyProvider>,
    /// Telemetry-style roots for Quick/Full scans, plus prefixes never scanned.
    pub scan_roots: ScanRoots,
}

/// Messages for the local desktop client (named pipe on Windows).
#[derive(Debug, Clone)]
pub enum LocalNotice {
    Frozen { alert_id: String, image_path: String, reason: String, elapsed_us: u64 },
    Blocked { image_path: String, reason: String },
    Alert { alert_id: String, severity: Severity, summary: String },
    CommandExecuted { command_id: String, ok: bool, reason: String },
    Scan { scan_id: String, state: pb::ScanState, files_seen: u64, findings: u64 },
}

pub fn pb_scan_state_name(s: pb::ScanState) -> &'static str {
    match s {
        pb::ScanState::Running => "running",
        pb::ScanState::Completed => "completed",
        pb::ScanState::Cancelled => "cancelled",
        pb::ScanState::Failed => "failed",
        pb::ScanState::Unspecified => "unspecified",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecDecision {
    Allow,
    /// Deny process creation (the driver completes it with STATUS_ACCESS_DENIED).
    Block,
}

/// Credential stores that only their owning process should read.
const CRED_STORES: &[&str] = &[
    r"\google\chrome\user data\default\login data",
    r"\google\chrome\user data\local state",
    r"\microsoft\edge\user data\default\login data",
    r"\mozilla\firefox\profiles\",
    r"\microsoft\credentials\",
    r"\microsoft\protect\",
    r"\windows\system32\config\sam",
];
const CRED_OWNERS: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "lsass.exe", "svchost.exe"];
const SCRIPT_IOCS: &[&str] = &[
    "downloadstring", "downloadfile", "frombase64string", "invoke-expression", "iex ", "iex(",
    "invoke-mimikatz", "-encodedcommand", "net.webclient", "bitsadmin", "reflection.assembly",
];

pub struct Engine {
    device_id: String,
    normalizer: Normalizer,
    resolve: PathResolver,
    /// Pseudonymized path → telemetry path. Cloud commands only ever carry
    /// pseudonymized paths; this resolves them locally.
    reverse_paths: HashMap<String, String>,
    seq: u64,
    spool: Spool,
    edge: Arc<EdgeEngine>,
    tier1: Tier1Policy,
    procs: Arc<dyn ProcessControl>,
    net: Arc<dyn NetworkControl>,
    canaries: CanarySet,
    beacons: BeaconTracker,
    mass: MassModifyTracker,
    allowlist: Arc<Mutex<Allowlist>>,
    verifier: CommandVerifier,
    executor: Executor,
    images: HashMap<ProcessKey, String>,
    alerted: HashSet<(ProcessKey, &'static str)>,
    pub outbox_alerts: VecDeque<pb::Alert>,
    pub outbox_results: VecDeque<CommandResult>,
    notices: Option<Sender<LocalNotice>>,
    pending_event_ids: Vec<String>,
    scan_roots: ScanRoots,
    pending_scans: Vec<ScanJob>,
    running_scans: HashMap<String, Arc<AtomicBool>>,
    pub outbox_scans: VecDeque<pb::ScanProgress>,
}

fn ts(ms: u64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds: (ms / 1000) as i64, nanos: ((ms % 1000) * 1_000_000) as i32 }
}

fn base_name(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_lowercase()
}

impl Engine {
    pub fn new(
        cfg: EngineConfig,
        edge: EdgeEngine,
        procs: Arc<dyn ProcessControl>,
        net: Arc<dyn NetworkControl>,
        resolve: PathResolver,
    ) -> Result<Self, BoxError> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let spool = Spool::open(&cfg.data_dir.join("spool.redb"), cfg.spool_cap_bytes)?;
        let seq = spool.last_seq()?;
        let vault = Arc::new(Vault::open(cfg.data_dir.join("vault"), cfg.vault_key)?);
        let allowlist = Arc::new(Mutex::new(Allowlist::load(cfg.data_dir.join("allowlist.txt"))?));
        let executor = Executor { procs: procs.clone(), net: net.clone(), vault, allowlist: allowlist.clone() };
        let verifier = CommandVerifier {
            device_id: cfg.device_id.clone(),
            keys: cfg.signing_keys,
            nonces: NonceStore::load(cfg.data_dir.join("nonces.tsv"))?,
        };
        Ok(Self {
            normalizer: Normalizer {
                device: DeviceInfo {
                    device_id: cfg.device_id.clone(),
                    os_name: cfg.os_name,
                    sensor_version: env!("CARGO_PKG_VERSION").into(),
                },
                pseudo: Pseudonymizer::new(cfg.pseudonym_salt),
            },
            device_id: cfg.device_id,
            resolve,
            reverse_paths: HashMap::new(),
            seq,
            spool,
            edge: Arc::new(edge),
            tier1: Tier1Policy::default(),
            procs,
            net,
            canaries: CanarySet::default(),
            beacons: BeaconTracker::default(),
            mass: MassModifyTracker::new(5_000, 50),
            allowlist,
            verifier,
            executor,
            images: HashMap::new(),
            alerted: HashSet::new(),
            outbox_alerts: VecDeque::new(),
            outbox_results: VecDeque::new(),
            notices: None,
            pending_event_ids: Vec::new(),
            scan_roots: cfg.scan_roots,
            pending_scans: Vec::new(),
            running_scans: HashMap::new(),
            outbox_scans: VecDeque::new(),
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn set_notice_sink(&mut self, tx: Sender<LocalNotice>) {
        self.notices = Some(tx);
    }

    fn notify(&self, n: LocalNotice) {
        if let Some(tx) = &self.notices {
            let _ = tx.send(n);
        }
    }

    /// Plans and writes canaries into `dirs` (telemetry paths). Returns the
    /// specs so the platform can mark them hidden and hand the list to the driver.
    pub fn deploy_canaries(&mut self, dirs: &[&str]) -> Result<Vec<CanarySpec>, BoxError> {
        let specs = canary::plan(&dirs.iter().map(PathBuf::from).collect::<Vec<_>>());
        for s in &specs {
            let real = (self.resolve)(&s.path.to_string_lossy());
            if let Some(parent) = real.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(real, &s.content)?;
        }
        self.canaries = CanarySet::new(&specs);
        Ok(specs)
    }

    fn pseudo_path(&mut self, path: &str) -> String {
        let p = self.normalizer.pseudo.path(path);
        if self.reverse_paths.len() > 50_000 {
            self.reverse_paths.clear();
        }
        self.reverse_paths.insert(p.clone(), path.to_string());
        p
    }

    fn process_ref(&mut self, p: ProcessKey, sha256: &str) -> ProcessRef {
        let image = self.images.get(&p).cloned().unwrap_or_default();
        ProcessRef {
            pid: p.pid,
            start_time_unix_ms: p.start_time_ms,
            image_path: self.pseudo_path(&image),
            sha256: sha256.to_string(),
            parent_pid: 0,
        }
    }

    // ----------------------------------------------------------------- telemetry

    /// Normalizes, spools, and runs streaming detectors on one event.
    pub fn ingest(&mut self, ev: RawEvent, time_ms: u64) -> Result<(), BoxError> {
        if let RawEvent::ProcessStart { process, image_path, .. } = &ev {
            self.images.insert(*process, image_path.clone());
        }
        let priority = match &ev {
            RawEvent::File { op: FileOp::Read, .. } => Priority::Bulk,
            RawEvent::File { .. } => Priority::Bulk,
            _ => Priority::Signal,
        };
        let event_id = self.spool_event(&ev, time_ms, priority)?;
        self.pending_event_ids.push(event_id);
        self.detect(&ev, time_ms);
        if self.pending_event_ids.len() > 64 {
            self.pending_event_ids.drain(..32);
        }
        if let RawEvent::ProcessStop { process, .. } = &ev {
            self.beacons.forget(*process);
            self.mass.forget(*process);
        }
        Ok(())
    }

    fn spool_event(&mut self, ev: &RawEvent, time_ms: u64, priority: Priority) -> Result<String, BoxError> {
        let (class_uid, ocsf) = self.normalizer.normalize(ev, time_ms);
        self.seq += 1;
        let event_id = uuid::Uuid::now_v7().to_string();
        let env = EventEnvelope {
            event_id: event_id.clone(),
            device_id: self.device_id.clone(),
            observed_at: Some(ts(time_ms)),
            ocsf_class_uid: class_uid,
            ocsf_json: serde_json::to_vec(&ocsf)?,
            seq: self.seq,
            priority: priority as i32,
        };
        self.spool.append(self.seq, priority as i32, &env.encode_to_vec())?;
        Ok(event_id)
    }

    fn detect(&mut self, ev: &RawEvent, t: u64) {
        match ev {
            RawEvent::File { process, image_path, path, op, .. } => {
                if *op != FileOp::Read {
                    if let Some(cid) = self.canaries.match_path(path).map(str::to_string) {
                        self.canary_trip(*process, image_path, path, &cid, op_name(*op), Instant::now());
                        return;
                    }
                    if let Some(n) = self.mass.observe(*process, path, t) {
                        let trig = Trigger::MassModify { files_in_window: n };
                        if self.tier1.should_freeze(&trig) && self.once(*process, "mass_modify") {
                            let outcome = self.tier1.freeze(self.procs.as_ref(), self.net.as_ref(), *process, image_path);
                            let reason = heuristic("mass_modify", 0.95, format!("files_5s={n}"));
                            self.raise(Some(*process), Severity::Critical, 0.95, reason, outcome.state, None, "", Some(outcome));
                        }
                    }
                } else {
                    let lower = path.to_lowercase();
                    let owner = base_name(image_path);
                    if CRED_STORES.iter().any(|c| lower.contains(c))
                        && !CRED_OWNERS.contains(&owner.as_str())
                        && self.once(*process, "credential_store_access")
                    {
                        let reason = heuristic("credential_store_access", 0.9, "non-owner read".into());
                        let p = self.pseudo_path(path);
                        self.raise(Some(*process), Severity::High, 0.9, reason, FreezeState::None, Some(p), "", None);
                    }
                }
            }
            RawEvent::Dns { process, query, .. } => {
                let (dga, tun) = (dga_score(query), dns_tunnel_score(query));
                if dga > 0.85 && self.once(*process, "dns_dga") {
                    let r = heuristic("dns_dga", dga, format!("score={dga:.2}"));
                    self.raise(Some(*process), Severity::Medium, dga, r, FreezeState::None, None, "", None);
                } else if tun > 0.85 && self.once(*process, "dns_tunnel") {
                    let r = heuristic("dns_tunnel", tun, format!("score={tun:.2}"));
                    self.raise(Some(*process), Severity::High, tun, r, FreezeState::None, None, "", None);
                }
            }
            RawEvent::Network { process, remote_addr, remote_port, .. } => {
                if let Some(b) = self.beacons.observe(*process, &format!("{remote_addr}:{remote_port}"), t) {
                    if self.once(*process, "beacon") {
                        let detail = format!("interval_ms={:.0} cv={:.3}", b.mean_interval_ms, b.jitter_cv);
                        let r = heuristic("beacon", 0.85, detail);
                        self.raise(Some(*process), Severity::High, 0.85, r, FreezeState::None, None, "", None);
                    }
                }
            }
            RawEvent::Script { process, content, .. } => {
                let lower = content.to_lowercase();
                let hits = SCRIPT_IOCS.iter().filter(|i| lower.contains(*i)).count();
                if hits >= 2 && self.once(*process, "script_download_exec") {
                    let score = (0.6 + 0.1 * hits as f32).min(0.95);
                    let r = heuristic("script_download_exec", score, format!("ioc_hits={hits}"));
                    self.raise(Some(*process), Severity::High, score, r, FreezeState::None, None, "", None);
                }
            }
            _ => {}
        }
    }

    fn once(&mut self, p: ProcessKey, what: &'static str) -> bool {
        self.alerted.insert((p, what))
    }

    #[allow(clippy::too_many_arguments)]
    fn raise(
        &mut self,
        p: Option<ProcessKey>,
        severity: Severity,
        confidence: f32,
        reason: Reason,
        tier1: FreezeState,
        file_path: Option<String>,
        file_sha256: &str,
        freeze: Option<FreezeOutcome>,
    ) -> String {
        let alert_id = format!("alr_{}", uuid::Uuid::now_v7().simple());
        let summary = match &reason {
            Reason::Heuristic(h) => h.name.clone(),
            Reason::Canary(_) => "ransomware_canary".into(),
            Reason::Bloom(_) => "known_malware_hash".into(),
            Reason::Ml(_) => "ml_static".into(),
            Reason::Yara(_) => "yara".into(),
        };
        let process = p.map(|p| self.process_ref(p, ""));
        let alert = pb::Alert {
            alert_id: alert_id.clone(),
            device_id: self.device_id.clone(),
            event_ids: self.pending_event_ids.iter().rev().take(16).cloned().collect(),
            severity: severity as i32,
            confidence,
            raised_at: Some(ts(enforcer::now_ms())),
            reason: Some(reason),
            tier1: tier1 as i32,
            process,
            file_path: file_path.unwrap_or_default(),
            file_sha256: file_sha256.to_string(),
            scan_id: String::new(),
        };
        tracing::warn!(%alert_id, %summary, ?severity, pid = p.map(|p| p.pid), "alert");
        // Spool a compact OCSF Detection Finding (2004) so the alert also survives offline.
        let finding = serde_json::json!({
            "class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401,
            "time": enforcer::now_ms(), "severity_id": severity as i32,
            "finding_info": { "uid": alert_id, "title": summary },
            "metadata": { "version": sensor_core::ocsf::OCSF_VERSION },
        });
        self.seq += 1;
        let env = EventEnvelope {
            event_id: uuid::Uuid::now_v7().to_string(),
            device_id: self.device_id.clone(),
            observed_at: Some(ts(enforcer::now_ms())),
            ocsf_class_uid: 2004,
            ocsf_json: serde_json::to_vec(&finding).unwrap_or_default(),
            seq: self.seq,
            priority: Priority::Critical as i32,
        };
        if let Err(e) = self.spool.append(self.seq, Priority::Critical as i32, &env.encode_to_vec()) {
            tracing::error!(error = %e, "failed to spool detection finding");
        }
        self.outbox_alerts.push_back(alert);
        match freeze {
            Some(f) => self.notify(LocalNotice::Frozen {
                alert_id: alert_id.clone(),
                image_path: p.and_then(|p| self.images.get(&p).cloned()).unwrap_or_default(),
                reason: summary,
                elapsed_us: f.elapsed_us,
            }),
            None => self.notify(LocalNotice::Alert { alert_id: alert_id.clone(), severity, summary }),
        }
        alert_id
    }

    // ------------------------------------------------------------ Tier-1 paths

    /// Called by the driver (or simulator) when a canary is touched. On Windows
    /// the minifilter has already denied the I/O; this freezes the process.
    pub fn canary_trip(
        &mut self,
        p: ProcessKey,
        image_path: &str,
        path: &str,
        canary_id: &str,
        op: &str,
        tripped_at: Instant,
    ) -> String {
        // The driver doesn't know image paths; fall back to what telemetry taught us.
        let image = if image_path.is_empty() {
            self.images.get(&p).cloned().unwrap_or_default()
        } else {
            self.images.entry(p).or_insert_with(|| image_path.to_string()).clone()
        };
        let outcome = self.tier1.freeze(self.procs.as_ref(), self.net.as_ref(), p, &image);
        let frozen_us = tripped_at.elapsed().as_micros() as u64;
        let pseudo = self.pseudo_path(path);
        let reason = Reason::Canary(pb::CanaryTrip {
            canary_id: canary_id.to_string(),
            operation: op.to_string(),
            trip_us: 0,
            frozen_us,
        });
        tracing::warn!(pid = p.pid, frozen_us, state = ?outcome.state, "canary trip → Tier-1 freeze");
        let mut o = outcome;
        o.elapsed_us = frozen_us;
        let state = o.state;
        self.raise(Some(p), Severity::Critical, 0.99, reason, state, Some(pseudo), "", Some(o))
    }

    /// Pre-execution gate: scores an image before its first thread runs.
    /// Known-bad (bloom) or ML+YARA-corroborated images are blocked; suspicious
    /// ones run but raise an alert for the cloud to correlate.
    pub fn pre_exec(&mut self, p: ProcessKey, image_path: &str) -> (ExecDecision, Option<Verdict>) {
        self.images.insert(p, image_path.to_string());
        let real = (self.resolve)(image_path);
        let v = match self.edge.analyze_file(&real) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "pre-exec: unreadable image, fail open");
                return (ExecDecision::Allow, None);
            }
        };
        if self.allowlist.lock().unwrap().contains(&v.sha256) {
            return (ExecDecision::Allow, Some(v));
        }
        let pseudo = self.pseudo_path(image_path);
        let trigger = if v.bloom_hit {
            Some(Trigger::BloomHit { sha256: v.sha256.clone() })
        } else {
            v.score.map(|s| Trigger::Ml { score: s, yara_matches: v.yara.len() })
        };
        let block = trigger.as_ref().is_some_and(|t| self.tier1.should_freeze(t));
        let reason = if v.bloom_hit {
            Reason::Bloom(pb::BloomHit { sha256: v.sha256.clone(), feed: "local".into() })
        } else {
            Reason::Ml(pb::MlVerdict {
                model_version: v.model_version.clone(),
                score: v.score.unwrap_or(0.0),
                top_features: v.top_features.clone(),
            })
        };
        match (block, v.decision) {
            (true, _) => {
                self.raise(Some(p), Severity::Critical, 0.99, reason, FreezeState::None, Some(pseudo), &v.sha256, None);
                self.notify(LocalNotice::Blocked { image_path: image_path.into(), reason: "pre-exec verdict".into() });
                (ExecDecision::Block, Some(v))
            }
            (false, Decision::Suspicious) | (false, Decision::Malicious) => {
                let conf = v.score.unwrap_or(0.8);
                self.raise(Some(p), Severity::High, conf, reason, FreezeState::None, Some(pseudo), &v.sha256, None);
                (ExecDecision::Allow, Some(v))
            }
            _ => (ExecDecision::Allow, Some(v)),
        }
    }

    // ------------------------------------------------------- cloud commands

    pub fn handle_command(&mut self, sc: &SignedCommand) -> CommandResult {
        let res = match self.verifier.verify(sc) {
            Err(reject) => {
                tracing::warn!(%reject, key_id = %sc.key_id, "rejected command");
                let cmd_id = pb::RemediationCommand::decode(sc.command.as_slice())
                    .map(|c| (c.command_id, c.action_id))
                    .unwrap_or_default();
                CommandResult {
                    command_id: cmd_id.0,
                    action_id: cmd_id.1,
                    status: CommandStatus::Rejected as i32,
                    reason: reject.to_string(),
                    vault_id: String::new(),
                    completed_at: Some(ts(enforcer::now_ms())),
                }
            }
            Ok(cmd) if matches!(cmd.tool, Some(Tool::StartScan(_)) | Some(Tool::CancelScan(_))) => self.scan_command(&cmd),
            Ok(mut cmd) => {
                // Resolve pseudonymized paths/images to local ones.
                match cmd.tool.as_mut() {
                    Some(Tool::Quarantine(q)) => {
                        let local = self.reverse_paths.get(&q.path).cloned().unwrap_or(q.path.clone());
                        q.path = (self.resolve)(&local).to_string_lossy().into_owned();
                    }
                    Some(Tool::NetBlock(pb::BlockProcessNetwork { process: Some(pr) }))
                    | Some(Tool::NetUnblock(pb::UnblockProcessNetwork { process: Some(pr) })) => {
                        let k = ProcessKey { pid: pr.pid, start_time_ms: pr.start_time_unix_ms };
                        if let Some(img) = self.images.get(&k) {
                            pr.image_path = img.clone();
                        }
                    }
                    _ => {}
                }
                self.executor.execute(&cmd)
            }
        };
        self.notify(LocalNotice::CommandExecuted {
            command_id: res.command_id.clone(),
            ok: res.status == CommandStatus::Executed as i32,
            reason: res.reason.clone(),
        });
        self.outbox_results.push_back(res.clone());
        res
    }

    // --------------------------------------------------------------- scans

    fn result(&self, cmd: &pb::RemediationCommand, ok: bool, reason: &str) -> CommandResult {
        CommandResult {
            command_id: cmd.command_id.clone(),
            action_id: cmd.action_id.clone(),
            status: if ok { CommandStatus::Executed } else { CommandStatus::Failed } as i32,
            reason: reason.into(),
            vault_id: String::new(),
            completed_at: Some(ts(enforcer::now_ms())),
        }
    }

    fn scan_command(&mut self, cmd: &pb::RemediationCommand) -> CommandResult {
        match &cmd.tool {
            Some(Tool::StartScan(s)) => {
                let scope = pb::ScanScope::try_from(s.scope).unwrap_or(pb::ScanScope::Unspecified);
                match self.queue_scan(&s.scan_id, scope) {
                    Ok(()) => self.result(cmd, true, ""),
                    Err(reason) => self.result(cmd, false, reason),
                }
            }
            Some(Tool::CancelScan(c)) => match self.running_scans.get(&c.scan_id) {
                Some(flag) => {
                    flag.store(true, Ordering::Relaxed);
                    self.result(cmd, true, "")
                }
                None => self.result(cmd, false, "SCAN_NOT_RUNNING"),
            },
            _ => self.result(cmd, false, "NOT_A_SCAN"),
        }
    }

    /// Queues a scan; `scan::spawn_pending` starts it on a background thread.
    pub fn queue_scan(&mut self, scan_id: &str, scope: pb::ScanScope) -> Result<(), &'static str> {
        let valid_id = scan_id.starts_with("scn_")
            && scan_id.len() <= 64
            && scan_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid_id {
            return Err("BAD_SCAN_ID");
        }
        if !self.running_scans.is_empty() {
            return Err("SCAN_ALREADY_RUNNING");
        }
        let roots = match scope {
            pb::ScanScope::Quick => self.scan_roots.quick.clone(),
            pb::ScanScope::Full => self.scan_roots.full.clone(),
            pb::ScanScope::Unspecified => return Err("BAD_SCOPE"),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.running_scans.insert(scan_id.to_string(), cancel.clone());
        self.pending_scans.push(ScanJob { scan_id: scan_id.to_string(), scope, roots, cancel });
        tracing::info!(%scan_id, ?scope, "scan queued");
        Ok(())
    }

    pub(crate) fn take_pending_scans(&mut self) -> Vec<(ScanJob, Arc<EdgeEngine>, PathResolver, Vec<String>)> {
        let jobs = std::mem::take(&mut self.pending_scans);
        jobs.into_iter()
            .map(|j| (j, self.edge.clone(), self.resolve.clone(), self.scan_roots.exclude.clone()))
            .collect()
    }

    pub fn scan_running(&self) -> bool {
        !self.running_scans.is_empty()
    }

    /// Progress from the scan thread. Terminal states release the scan slot.
    pub fn scan_progress(&mut self, mut p: pb::ScanProgress) {
        p.current_path = self.normalizer.pseudo.path(&p.current_path);
        let state = pb::ScanState::try_from(p.state).unwrap_or(pb::ScanState::Unspecified);
        if state != pb::ScanState::Running {
            self.running_scans.remove(&p.scan_id);
            tracing::info!(scan_id = %p.scan_id, ?state, seen = p.files_seen, analyzed = p.files_analyzed, findings = p.findings, "scan finished");
        }
        self.notify(LocalNotice::Scan { scan_id: p.scan_id.clone(), state, files_seen: p.files_seen, findings: p.findings });
        // Only the latest RUNNING update matters; keep terminal ones.
        self.outbox_scans.retain(|q| !(q.scan_id == p.scan_id && q.state == pb::ScanState::Running as i32));
        self.outbox_scans.push_back(p);
    }

    /// A malicious or suspicious file found at rest. Raises an alert (no process,
    /// nothing to freeze); remediation goes through the normal HITL flow.
    pub fn scan_finding(&mut self, scan_id: &str, path: &str, v: &Verdict) {
        if self.allowlist.lock().unwrap().contains(&v.sha256) {
            return;
        }
        let pseudo = self.pseudo_path(path);
        let (reason, severity) = if v.bloom_hit {
            (Reason::Bloom(pb::BloomHit { sha256: v.sha256.clone(), feed: "local".into() }), Severity::Critical)
        } else {
            let r = Reason::Ml(pb::MlVerdict {
                model_version: v.model_version.clone(),
                score: v.score.unwrap_or(0.0),
                top_features: v.top_features.clone(),
            });
            (r, if v.decision == Decision::Malicious { Severity::Critical } else { Severity::High })
        };
        let conf = if v.bloom_hit { 0.99 } else { v.score.unwrap_or(0.8) };
        self.raise(None, severity, conf, reason, FreezeState::None, Some(pseudo), &v.sha256, None);
        if let Some(a) = self.outbox_alerts.back_mut() {
            a.scan_id = scan_id.to_string();
        }
    }

    // ------------------------------------------------------------- uplink

    pub fn batch_after(&mut self, after: u64, limit: usize) -> Result<(EventBatch, u64), BoxError> {
        let rows = self.spool.batch_after(after, limit)?;
        let last = rows.last().map(|r| r.0).unwrap_or(after);
        let events = rows
            .into_iter()
            .filter_map(|(_, b)| EventEnvelope::decode(b.as_slice()).ok())
            .collect();
        Ok((EventBatch { events, dropped_since_last: self.spool.take_dropped() }, last))
    }

    pub fn ack(&mut self, seq: u64) -> Result<(), BoxError> {
        self.spool.ack(seq)?;
        Ok(())
    }

    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    pub fn edge_model_version(&self) -> String {
        self.edge.scorer.version().to_string()
    }
}

fn heuristic(name: &str, score: f32, detail: String) -> Reason {
    Reason::Heuristic(pb::Heuristic { name: name.into(), score, detail })
}

fn op_name(op: FileOp) -> &'static str {
    match op {
        FileOp::Write => "WRITE",
        FileOp::Rename => "RENAME",
        FileOp::Delete => "DELETE",
        FileOp::SetInfo => "SET_INFO",
        FileOp::Create => "CREATE",
        FileOp::Read => "READ",
    }
}

#[cfg(test)]
mod tests;
