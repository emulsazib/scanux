//! sensor-sim: drives the real sensor engine with scripted telemetry.
//!
//!   sensor-sim --device dev-sim-1 scenario office-cred-theft --linger 300
//!   sensor-sim --offline scenario ransomware
//!
//! Everything except the OS layer is production code: OCSF normalization,
//! detectors, Tier-1 freeze, spool, mTLS uplink, Ed25519 command verification,
//! vault. The OS layer is `sensor_core::mock::MockPlatform`.

mod scenarios;

use clap::{Parser, Subcommand};
use ed25519_dalek::pkcs8::DecodePublicKey;
use engine::uplink::{self, UplinkConfig};
use engine::{Engine, EngineConfig, LocalNotice};
use sensor_core::mock::MockPlatform;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scanu_proto::v1::ScanScope as scanu_scope;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SCANU_GATEWAY", default_value = "https://localhost:7443")]
    gateway: String,
    #[arg(long, env = "SCANU_PKI", default_value = "deploy/pki/out")]
    pki: PathBuf,
    #[arg(long, default_value = "dev-sim-1")]
    device: String,
    /// Persistent sensor state (spool, vault, nonces). Defaults to .data/sim/<device>.
    #[arg(long)]
    data: Option<PathBuf>,
    /// Do not connect to the cloud (demonstrates offline Tier-1).
    #[arg(long)]
    offline: bool,
    /// Run a local scan after the scenario: quick | full.
    #[arg(long, global = true)]
    scan: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Scenario {
        /// office-cred-theft | ransomware | dormant | benign | all
        name: String,
        /// Seconds to stay connected afterwards to receive approved commands.
        #[arg(long, default_value_t = 5)]
        linger: u64,
    },
}

fn read(p: &PathBuf) -> anyhow::Result<Vec<u8>> {
    std::fs::read(p).map_err(|e| anyhow::anyhow!("{}: {e} (run `make pki`)", p.display()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let Cmd::Scenario { name, linger } = args.cmd;
    let data = args.data.clone().unwrap_or_else(|| PathBuf::from(".data/sim").join(&args.device));
    let fs_root = data.join("fs");

    let mut keys = HashMap::new();
    if let Ok(pem) = std::fs::read_to_string(args.pki.join("cmd-signing.pub.pem")) {
        let key_id = std::fs::read_to_string(args.pki.join("cmd-signing.key_id"))?.trim().to_string();
        keys.insert(key_id, ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)?);
    } else if !args.offline {
        anyhow::bail!("missing {}/cmd-signing.pub.pem (run `make pki`)", args.pki.display());
    }

    let plat = Arc::new(MockPlatform::default());
    let salt: [u8; 16] = Sha256::digest(args.device.as_bytes())[..16].try_into()?;
    let cfg = EngineConfig {
        device_id: args.device.clone(),
        os_name: "Windows".into(),
        data_dir: data.clone(),
        spool_cap_bytes: 64 << 20,
        pseudonym_salt: salt,
        signing_keys: keys,
        // Dev only: production derives this from a TPM-sealed secret.
        vault_key: Box::new(vault::StaticKey(Sha256::digest(format!("sim-vault-{}", args.device)).into())),
        scan_roots: engine::scan::ScanRoots {
            quick: ["Downloads", "Desktop", r"AppData\Local\Temp", r"AppData\Roaming"]
                .iter()
                .map(|d| format!(r"C:\Users\alice\{d}"))
                .chain([r"C:\ProgramData".to_string()])
                .collect(),
            full: vec![r"C:\".into()],
            exclude: vec![r"c:\programdata\scanu".into()],
        },
    };
    // Local known-bad feed: contains the synthetic "known malware" planted by the dormant scenario.
    let mut bloom = edge_ml::Bloom::with_capacity(1_000, 0.0001);
    bloom.insert(&Sha256::digest(scenarios::known_bad_sample()).into());
    let edge = edge_ml::EdgeEngine::new(Some(bloom), Box::new(edge_ml::LinearScorer::baseline()));
    let root = fs_root.clone();
    let resolver: engine::engine::PathResolver =
        Arc::new(move |p: &str| root.join(p.replace(':', "").replace('\\', "/")));
    let mut eng = Engine::new(cfg, edge, plat.clone(), plat.clone(), resolver).map_err(|e| anyhow::anyhow!(e))?;
    let (ntx, nrx) = std::sync::mpsc::channel();
    eng.set_notice_sink(ntx);
    let engine = Arc::new(Mutex::new(eng));

    // Desktop-client stand-in: print local notices.
    std::thread::spawn(move || {
        for n in nrx {
            match n {
                LocalNotice::Frozen { image_path, reason, elapsed_us, .. } => {
                    println!("🧊 TIER-1 FREEZE  {image_path}  reason={reason}  frozen_in={elapsed_us}µs");
                    println!("   → Tier-2 prompt: [Terminate & Quarantine] [Isolate Network Only] [Allow & Whitelist]");
                }
                LocalNotice::Blocked { image_path, reason } => println!("⛔ BLOCKED  {image_path}  ({reason})"),
                LocalNotice::Alert { severity, summary, .. } => println!("⚠️  ALERT  {summary}  severity={severity:?}"),
                LocalNotice::Scan { scan_id, state, files_seen, findings } => {
                    use engine::engine::pb_scan_state_name as name;
                    println!("🔎 SCAN {scan_id} {}  files={files_seen} findings={findings}", name(state));
                }
                LocalNotice::CommandExecuted { command_id, ok, reason } => {
                    println!("{} COMMAND {command_id} {}", if ok { "✅" } else { "❌" }, if ok { "executed".into() } else { reason });
                }
            }
        }
    });

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uplink_task = if args.offline {
        println!("offline mode: no cloud connection; local protection only");
        None
    } else {
        let dev = args.pki.join("devices");
        let cfg = UplinkConfig {
            endpoint: args.gateway.clone(),
            domain: "localhost".into(),
            ca_pem: read(&args.pki.join("ca.pem"))?,
            cert_pem: read(&dev.join(format!("{}.pem", args.device)))?,
            key_pem: read(&dev.join(format!("{}.key", args.device)))?,
            os: "Windows (simulated)".into(),
            batch_size: 500,
            flush_every: Duration::from_millis(500),
        };
        Some(tokio::spawn(uplink::run(engine.clone(), cfg, stop_rx)))
    };

    {
        let mut e = engine.lock().unwrap();
        let names: Vec<&str> =
            if name == "all" { vec!["benign", "office-cred-theft", "ransomware", "dormant"] } else { vec![name.as_str()] };
        for n in names {
            println!("\n=== scenario: {n} ===");
            scenarios::run(n, &mut e, &plat, &fs_root)?;
        }
    }

    if let Some(scope) = &args.scan {
        let scope = if scope == "full" { scanu_scope::Full } else { scanu_scope::Quick };
        match engine::scan::start_local(&engine, scope) {
            Ok(id) => println!("\nlocal scan {id} started"),
            Err(e) => println!("\nlocal scan refused: {e}"),
        }
    }

    println!("\nlingering {linger}s for cloud commands (Ctrl-C to stop)…");
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(linger)) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    stop_tx.send(true).ok();
    if let Some(t) = uplink_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }
    println!("\nplatform actions: {:?}", plat.actions());
    Ok(())
}
