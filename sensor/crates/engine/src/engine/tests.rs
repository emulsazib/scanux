use super::*;
use ed25519_dalek::{Signer, SigningKey};
use sensor_core::mock::{MockPlatform, ProcState};
use std::path::Path;

struct Rig {
    _dir: tempfile::TempDir,
    root: PathBuf,
    plat: Arc<MockPlatform>,
    engine: Engine,
    sk: SigningKey,
}

/// Maps `C:\...` telemetry paths into the temp dir.
fn resolver(root: PathBuf) -> PathResolver {
    Arc::new(move |p: &str| root.join(p.replace(':', "").replace('\\', "/")))
}

fn rig(bloom: Option<edge_ml::Bloom>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fs");
    let plat = Arc::new(MockPlatform::default());
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let cfg = EngineConfig {
        device_id: "dev-1".into(),
        os_name: "Windows".into(),
        data_dir: dir.path().join("data"),
        spool_cap_bytes: 8 << 20,
        pseudonym_salt: [3; 16],
        signing_keys: HashMap::from([("k1".to_string(), sk.verifying_key())]),
        vault_key: Box::new(vault::StaticKey([5; 32])),
        scan_roots: crate::scan::ScanRoots {
            quick: vec![r"C:\Users\alice\Downloads".into()],
            full: vec![r"C:\".into()],
            exclude: vec![r"c:\programdata\scanu".into()],
        },
    };
    let edge = EdgeEngine::new(bloom, Box::new(edge_ml::LinearScorer::baseline()));
    let engine = Engine::new(cfg, edge, plat.clone(), plat.clone(), resolver(root.clone())).unwrap();
    Rig { _dir: dir, root, plat, engine, sk }
}

fn key(pid: u32) -> ProcessKey {
    ProcessKey { pid, start_time_ms: 1000 + pid as u64 }
}

fn start(r: &mut Rig, pid: u32, image: &str) {
    r.plat.spawn(key(pid));
    r.engine
        .ingest(
            RawEvent::ProcessStart {
                process: key(pid),
                parent: None,
                image_path: image.into(),
                cmdline: image.into(),
                user: "alice".into(),
                sha256: None,
            },
            1,
        )
        .unwrap();
}

fn write_real(r: &Rig, tele_path: &str, data: &[u8]) {
    let p = r.root.join(tele_path.replace(':', "").replace('\\', "/"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn signed(r: &Rig, nonce: u64, tool: Tool, approval: &str) -> SignedCommand {
    signed_with(&r.sk, nonce, tool, approval)
}

fn signed_with(sk: &SigningKey, nonce: u64, tool: Tool, approval: &str) -> SignedCommand {
    let na = enforcer::now_ms() + 60_000;
    let cmd = pb::RemediationCommand {
        command_id: format!("c{nonce}"),
        action_id: "a1".into(),
        device_id: "dev-1".into(),
        not_after: Some(ts(na)),
        nonce,
        approval_ref: approval.into(),
        tool: Some(tool),
    };
    let bytes = cmd.encode_to_vec();
    SignedCommand { ed25519_sig: sk.sign(&bytes).to_bytes().to_vec(), command: bytes, key_id: "k1".into() }
}

#[test]
fn canary_write_freezes_process_under_100ms() {
    let mut r = rig(None);
    let specs = r.engine.deploy_canaries(&[r"C:\Users\alice\Documents"]).unwrap();
    let img = r"C:\Users\alice\Downloads\invoice.exe";
    start(&mut r, 50, img);
    let canary = specs[0].path.to_string_lossy().to_string();
    assert!(Path::new(&r.root.join(canary.replace(':', "").replace('\\', "/"))).exists());
    r.engine
        .ingest(RawEvent::File { process: key(50), image_path: img.into(), path: canary, op: FileOp::Write, new_path: None }, 2)
        .unwrap();
    assert_eq!(r.plat.state(key(50)), Some(ProcState::Suspended));
    assert!(r.plat.is_blocked(img));
    let a = r.engine.outbox_alerts.pop_back().unwrap();
    assert_eq!(a.tier1, FreezeState::SuspendedAndNetBlocked as i32);
    let Some(Reason::Canary(c)) = a.reason else { panic!("expected canary reason") };
    assert!(c.frozen_us < 100_000, "froze in {}us", c.frozen_us);
    assert!(!a.file_path.contains("alice"), "pseudonymized: {}", a.file_path);
}

#[test]
fn pre_exec_blocks_bloom_hit_and_alerts_on_suspicious() {
    let bad = edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::PackedRwx);
    let img = r"C:\Users\alice\AppData\Local\Temp\upd.exe";

    let mut r = rig(None);
    write_real(&r, img, &bad);
    let (d, v) = r.engine.pre_exec(key(60), img);
    assert_eq!(d, ExecDecision::Allow, "ML alone never blocks: {v:?}");
    assert_eq!(r.engine.outbox_alerts.len(), 1);

    let mut b = edge_ml::Bloom::with_capacity(10, 0.001);
    b.insert(&sha2_digest(&bad));
    let mut r = rig(Some(b));
    write_real(&r, img, &bad);
    let (d, _) = r.engine.pre_exec(key(61), img);
    assert_eq!(d, ExecDecision::Block);
}

fn sha2_digest(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

#[test]
fn approved_terminate_and_quarantine_then_rollback() {
    let mut r = rig(None);
    let img = r"C:\Users\alice\AppData\Local\Temp\upd.exe";
    let body = b"MZ not really a pe".to_vec();
    write_real(&r, img, &body);
    start(&mut r, 70, img);
    // Cloud sees only the pseudonymized path, via the alert.
    r.engine.pre_exec(key(70), img);
    let pseudo = r.engine.normalizer.pseudo.path(img);
    let pr = ProcessRef { pid: 70, start_time_unix_ms: key(70).start_time_ms, ..Default::default() };

    let res = r.engine.handle_command(&signed(&r, 1, Tool::Terminate(pb::TerminateProcess { process: Some(pr.clone()) }), "dec-1"));
    assert_eq!(res.status, CommandStatus::Executed as i32, "{res:?}");
    assert_eq!(r.plat.state(key(70)), Some(ProcState::Terminated));

    let sha = hex::encode(sha2_digest(&body));
    let q = Tool::Quarantine(pb::QuarantineFile { path: pseudo, sha256: sha });
    let res = r.engine.handle_command(&signed(&r, 2, q, "dec-1"));
    assert_eq!(res.status, CommandStatus::Executed as i32, "{res:?}");
    let real = r.root.join(img.replace(':', "").replace('\\', "/"));
    assert!(!real.exists());

    let res = r.engine.handle_command(&signed(&r, 3, Tool::Restore(pb::RestoreFromVault { vault_id: res.vault_id }), "dec-2"));
    assert_eq!(res.status, CommandStatus::Executed as i32, "{res:?}");
    assert_eq!(std::fs::read(real).unwrap(), body);
}

#[test]
fn pid_reuse_and_unapproved_commands_fail() {
    let mut r = rig(None);
    start(&mut r, 80, "a.exe");
    let stale = ProcessRef { pid: 80, start_time_unix_ms: 1, ..Default::default() };
    let res = r.engine.handle_command(&signed(&r, 1, Tool::Terminate(pb::TerminateProcess { process: Some(stale) }), "dec"));
    assert_eq!((res.status, res.reason.as_str()), (CommandStatus::Failed as i32, "PID_REUSED"));
    let pr = ProcessRef { pid: 80, start_time_unix_ms: key(80).start_time_ms, ..Default::default() };
    let res = r.engine.handle_command(&signed(&r, 2, Tool::Terminate(pb::TerminateProcess { process: Some(pr) }), ""));
    assert_eq!((res.status, res.reason.as_str()), (CommandStatus::Rejected as i32, "APPROVAL_REQUIRED"));
    assert_eq!(r.plat.state(key(80)), Some(ProcState::Running));
}

#[test]
fn credential_store_read_by_non_browser_alerts_once() {
    let mut r = rig(None);
    start(&mut r, 90, r"C:\Users\alice\AppData\Local\Temp\upd.exe");
    for _ in 0..3 {
        r.engine
            .ingest(
                RawEvent::File {
                    process: key(90),
                    image_path: r"C:\Users\alice\AppData\Local\Temp\upd.exe".into(),
                    path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data".into(),
                    op: FileOp::Read,
                    new_path: None,
                },
                3,
            )
            .unwrap();
    }
    assert_eq!(r.engine.outbox_alerts.len(), 1);
}

#[test]
fn spool_holds_events_while_offline_and_acks_trim() {
    let mut r = rig(None);
    start(&mut r, 1, "a.exe");
    start(&mut r, 2, "b.exe");
    let (batch, last) = r.engine.batch_after(0, 100).unwrap();
    assert_eq!(batch.events.len(), 2);
    assert!(batch.events.iter().all(|e| e.device_id == "dev-1" && e.ocsf_class_uid == 1007));
    r.engine.ack(last).unwrap();
    assert_eq!(r.engine.batch_after(0, 100).unwrap().0.events.len(), 0);
}

fn wait_scan(engine: &Arc<Mutex<Engine>>) -> pb::ScanProgress {
    let t0 = Instant::now();
    while engine.lock().unwrap().scan_running() {
        assert!(t0.elapsed().as_secs() < 20, "scan did not finish");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let e = engine.lock().unwrap();
    e.outbox_scans.iter().rev().find(|p| p.state != pb::ScanState::Running as i32).cloned().expect("terminal progress")
}

#[test]
fn quick_scan_finds_dormant_malware_without_touching_it() {
    let known_bad = [edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::Benign), b"KNOWN-BAD".to_vec()].concat();
    let mut bloom = edge_ml::Bloom::with_capacity(10, 0.001);
    bloom.insert(&sha2_digest(&known_bad));
    let r = rig(Some(bloom));
    let dl = r"C:\Users\alice\Downloads";
    write_real(&r, &format!(r"{dl}\setup.exe"), &edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::Benign));
    write_real(&r, &format!(r"{dl}\invoice_viewer.exe"), &edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::PackedRwx));
    write_real(&r, &format!(r"{dl}\nested\deeper\updater.exe"), &known_bad);
    write_real(&r, &format!(r"{dl}\notes.txt"), &[b'a'; 500]);
    write_real(&r, r"C:\Users\alice\Documents\other.exe", &edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::PackedRwx));
    let root = r.root.clone();
    let engine = Arc::new(Mutex::new(r.engine));
    let id = crate::scan::start_local(&engine, pb::ScanScope::Quick).unwrap();
    let done = wait_scan(&engine);
    assert_eq!(done.scan_id, id);
    assert_eq!(done.state, pb::ScanState::Completed as i32);
    assert_eq!((done.files_seen, done.files_analyzed, done.findings), (4, 3, 2), "{done:?}");
    let e = engine.lock().unwrap();
    let alerts: Vec<_> = e.outbox_alerts.iter().filter(|a| a.scan_id == id).collect();
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().any(|a| matches!(a.reason, Some(Reason::Bloom(_))) && a.severity == Severity::Critical as i32));
    assert!(alerts.iter().all(|a| a.process.is_none() && !a.file_sha256.is_empty() && !a.file_path.contains("alice")));
    // Read-only: nothing moved, nothing frozen.
    assert!(root.join("C/Users/alice/Downloads/invoice_viewer.exe").exists());
    assert!(r.plat.actions().is_empty());
}

#[test]
fn scan_commands_are_validated_and_exclusive() {
    let r = rig(None);
    let mut e = r.engine;
    assert_eq!(e.queue_scan("bad id", pb::ScanScope::Full), Err("BAD_SCAN_ID"));
    assert_eq!(e.queue_scan("scn_1", pb::ScanScope::Unspecified), Err("BAD_SCOPE"));
    e.queue_scan("scn_1", pb::ScanScope::Full).unwrap();
    assert_eq!(e.queue_scan("scn_2", pb::ScanScope::Quick), Err("SCAN_ALREADY_RUNNING"));
    // Signed cancel for an unknown scan fails cleanly; for the queued one it succeeds.
    let res = e.handle_command(&signed_with(&r.sk, 1, Tool::CancelScan(pb::CancelScan { scan_id: "scn_x".into() }), ""));
    assert_eq!(res.reason, "SCAN_NOT_RUNNING");
    let res = e.handle_command(&signed_with(&r.sk, 2, Tool::CancelScan(pb::CancelScan { scan_id: "scn_1".into() }), ""));
    assert_eq!(res.status, CommandStatus::Executed as i32);
}

#[test]
fn signed_start_scan_runs_and_can_be_cancelled() {
    let r = rig(None);
    for i in 0..400 {
        write_real(&r, &format!(r"C:\Users\alice\Downloads\f{i}.exe"), &edge_ml::testpe::tiny_pe64(edge_ml::testpe::Shape::Benign));
    }
    let sk = r.sk.clone();
    let engine = Arc::new(Mutex::new(r.engine));
    let start = signed_with(&sk, 1, Tool::StartScan(pb::StartScan { scan_id: "scn_cloud1".into(), scope: pb::ScanScope::Full as i32 }), "");
    let res = engine.lock().unwrap().handle_command(&start);
    assert_eq!(res.status, CommandStatus::Executed as i32, "{res:?}");
    crate::scan::spawn_pending(&engine);
    let cancel = signed_with(&sk, 2, Tool::CancelScan(pb::CancelScan { scan_id: "scn_cloud1".into() }), "");
    engine.lock().unwrap().handle_command(&cancel);
    let done = wait_scan(&engine);
    assert!(
        done.state == pb::ScanState::Cancelled as i32 || done.state == pb::ScanState::Completed as i32,
        "{done:?}"
    );
}
