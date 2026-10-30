use ed25519_dalek::pkcs8::DecodePublicKey;
use engine::uplink::{self, UplinkConfig};
use engine::{Engine, EngineConfig, ExecDecision, LocalNotice};
use scanu_proto::v1::ScanScope;
use sensor_core::platform::EventSource;
use sensor_core::RawEvent;
use sensor_win::driver::{DriverEvent, DriverPort};
use sensor_win::etw::EtwSource;
use sensor_win::eventlog::EventLogSource;
use sensor_win::keys::DpapiKey;
use sensor_win::process::WinProcessControl;
use sensor_win::wfp::WinNetworkControl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "ScanuSensor";
const ROOT: &str = r"C:\ProgramData\Scanu";
const PIPE: &str = r"\\.\pipe\scanu-desktop";
/// SYSTEM full control; interactive users read/write. Users get notices and may
/// request *read-only* actions (status, scan); nothing destructive is accepted here.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;IU)";

fn root() -> PathBuf {
    PathBuf::from(ROOT)
}

/// `C:\ProgramData\Scanu\sensor.json`. Every field is optional: with no file the
/// sensor runs in standalone mode (local protection, no cloud link).
#[derive(Deserialize, Serialize)]
struct Config {
    #[serde(default)]
    device_id: String,
    /// `https://host:port` of the Scanu ingest gateway; absent = standalone.
    #[serde(default)]
    gateway: Option<String>,
    /// TLS server name in the gateway certificate (defaults to the URL host).
    #[serde(default)]
    gateway_tls_name: Option<String>,
    #[serde(default = "default_pki")]
    pki_dir: PathBuf,
    #[serde(default = "default_data")]
    data_dir: PathBuf,
    /// Empty = every user's Documents and Pictures.
    #[serde(default)]
    canary_dirs: Vec<String>,
    #[serde(default)]
    bloom_path: Option<PathBuf>,
}

fn default_pki() -> PathBuf {
    root().join("pki")
}

fn default_data() -> PathBuf {
    root().join("data")
}

impl Config {
    fn path() -> PathBuf {
        root().join("sensor.json")
    }

    fn load() -> Self {
        let mut c: Config = std::fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| serde_json::from_str("{}").expect("defaults"));
        if c.device_id.is_empty() {
            c.device_id = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows-device".into()).to_lowercase();
        }
        if c.canary_dirs.is_empty() {
            c.canary_dirs = user_homes()
                .into_iter()
                .flat_map(|h| [format!(r"{h}\Documents"), format!(r"{h}\Pictures")])
                .filter(|d| Path::new(d).is_dir())
                .collect();
        }
        c
    }

    fn tls_name(&self) -> String {
        self.gateway_tls_name.clone().unwrap_or_else(|| {
            let g = self.gateway.as_deref().unwrap_or_default();
            let host = g.split("://").nth(1).unwrap_or(g);
            host.split([':', '/']).next().unwrap_or(host).to_string()
        })
    }
}

/// Real user profiles under C:\Users (skips the built-in template profiles).
fn user_homes() -> Vec<String> {
    const SKIP: &[&str] = &["public", "default", "default user", "all users", "defaultapppool"];
    std::fs::read_dir(r"C:\Users")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter(|e| !SKIP.contains(&e.file_name().to_string_lossy().to_lowercase().as_str()))
                .map(|e| e.path().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

define_windows_service!(ffi_service_main, service_main);

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version") => println!("scanu-sensor {}", env!("CARGO_PKG_VERSION")),
        Some("enroll") => {
            console_log();
            let code = match enroll(args.get(2).map(PathBuf::from)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("enroll failed: {e}");
                    1
                }
            };
            std::process::exit(code);
        }
        Some("--console") => {
            console_log();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s); // Enter stops console mode
                let _ = tx.send(());
            });
            if let Err(e) = run(rx) {
                tracing::error!(error = %e, "sensor failed");
            }
        }
        _ => {
            file_log();
            if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                eprintln!("not started by the Service Control Manager ({e}). Use --console, enroll <file>, or --version.");
            }
        }
    }
}

fn console_log() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
}

/// Service mode logs to C:\ProgramData\Scanu\logs\sensor.log (truncated past 20 MB).
fn file_log() {
    let dir = root().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("sensor.log");
    if std::fs::metadata(&path).map(|m| m.len() > 20 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("sensor.log.1"));
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(Mutex::new(f)).init(),
        Err(_) => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Enrollment bundle produced by `devpki bundle` (or the cloud console later).
#[derive(Deserialize)]
struct Bundle {
    device_id: String,
    gateway: String,
    #[serde(default)]
    gateway_tls_name: Option<String>,
    ca_pem: String,
    device_cert_pem: String,
    device_key_pem: String,
    cmd_signing_pub_pem: String,
    cmd_signing_key_id: String,
}

/// `scanu-sensor.exe enroll <bundle.json>` (elevated): links this device to a Scanu cloud.
fn enroll(path: Option<PathBuf>) -> R<()> {
    let path = path.ok_or("usage: scanu-sensor.exe enroll <enrollment.json>")?;
    let b: Bundle = serde_json::from_slice(&std::fs::read(&path)?)?;
    if !b.gateway.starts_with("https://") {
        return Err("gateway must be an https:// URL".into());
    }
    ed25519_dalek::VerifyingKey::from_public_key_pem(&b.cmd_signing_pub_pem).map_err(|e| format!("bad signing key: {e}"))?;
    let valid_id = !b.device_id.is_empty() && b.device_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !valid_id || b.cmd_signing_key_id.trim().is_empty() {
        return Err("bundle is missing device_id or cmd_signing_key_id".into());
    }
    let mut cfg = Config::load();
    std::fs::create_dir_all(&cfg.pki_dir)?;
    for (name, body) in [
        ("ca.pem", &b.ca_pem),
        ("device.pem", &b.device_cert_pem),
        ("device.key", &b.device_key_pem),
        ("cmd-signing.pub.pem", &b.cmd_signing_pub_pem),
        ("cmd-signing.key_id", &b.cmd_signing_key_id),
    ] {
        std::fs::write(cfg.pki_dir.join(name), body)?;
    }
    cfg.device_id = b.device_id;
    cfg.gateway = Some(b.gateway);
    cfg.gateway_tls_name = b.gateway_tls_name;
    std::fs::write(Config::path(), serde_json::to_vec_pretty(&cfg)?)?;
    println!("Enrolled as {} → {}. Restarting the Scanu sensor…", cfg.device_id, cfg.gateway.as_deref().unwrap_or_default());
    let sc = |verb: &str| std::process::Command::new("sc.exe").args([verb, SERVICE_NAME]).output();
    let _ = sc("stop");
    std::thread::sleep(Duration::from_secs(3));
    sc("start")?;
    println!("Done. You can delete {} now; it contains the device private key.", path.display());
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else { return };
    let set = |state| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    set(ServiceState::Running);
    if let Err(e) = run(rx) {
        tracing::error!(error = %e, "sensor failed");
    }
    set(ServiceState::Stopped);
}

struct Status {
    device_id: String,
    cloud: bool,
    driver: bool,
}

fn run(stop: std::sync::mpsc::Receiver<()>) -> R<()> {
    let cfg = Config::load();
    std::fs::create_dir_all(&cfg.data_dir)?;

    // Cloud link is optional: without enrollment the sensor runs standalone.
    let mut keys = HashMap::new();
    let pki = &cfg.pki_dir;
    if let (Ok(pem), Ok(key_id)) = (
        std::fs::read_to_string(pki.join("cmd-signing.pub.pem")),
        std::fs::read_to_string(pki.join("cmd-signing.key_id")),
    ) {
        keys.insert(key_id.trim().to_string(), ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)?);
    }
    let uplink_cfg = match (&cfg.gateway, std::fs::read(pki.join("ca.pem")), std::fs::read(pki.join("device.pem")), std::fs::read(pki.join("device.key"))) {
        (Some(gw), Ok(ca), Ok(cert), Ok(key)) if !keys.is_empty() => Some(UplinkConfig {
            endpoint: gw.clone(),
            domain: cfg.tls_name(),
            ca_pem: ca,
            cert_pem: cert,
            key_pem: key,
            os: "Windows".into(),
            batch_size: 500,
            flush_every: Duration::from_secs(2),
        }),
        _ => None,
    };

    let procs = Arc::new(WinProcessControl);
    let net = Arc::new(WinNetworkControl::open()?);
    let bloom = cfg
        .bloom_path
        .as_ref()
        .and_then(|p| std::fs::File::open(p).ok())
        .and_then(|mut f| edge_ml::Bloom::read_from(&mut f).ok());
    let edge = edge_ml::EdgeEngine::new(bloom, Box::new(edge_ml::LinearScorer::baseline()));
    let salt: [u8; 16] = Sha256::digest(cfg.device_id.as_bytes())[..16].try_into()?;
    let econf = EngineConfig {
        device_id: cfg.device_id.clone(),
        os_name: "Windows".into(),
        data_dir: cfg.data_dir.clone(),
        spool_cap_bytes: 256 << 20,
        pseudonym_salt: salt,
        signing_keys: keys,
        vault_key: Box::new(DpapiKey::new(cfg.data_dir.join("vault.key"))),
        scan_roots: scan_roots(&cfg.data_dir),
    };
    let mut eng = Engine::new(econf, edge, procs, net, Arc::new(|p: &str| PathBuf::from(p)))?;
    let (ntx, nrx) = std::sync::mpsc::channel::<LocalNotice>();
    eng.set_notice_sink(ntx);

    let dirs: Vec<&str> = cfg.canary_dirs.iter().map(String::as_str).collect();
    let specs = eng.deploy_canaries(&dirs)?;
    for s in &specs {
        hide(&s.path);
    }
    let canary_paths: sensor_win::etw::CanaryPaths =
        Arc::new(std::sync::RwLock::new(specs.iter().map(|s| s.path.to_string_lossy().to_lowercase()).collect()));
    let engine = Arc::new(Mutex::new(eng));

    let driver = match DriverPort::connect() {
        Ok(d) => {
            d.set_canaries(&specs.iter().map(|s| s.path.to_string_lossy().into_owned()).collect::<Vec<_>>())?;
            d.protect_prefix(&cfg.data_dir.to_string_lossy())?;
            tracing::info!("minifilter connected: kernel canary + pre-exec + self-protection active");
            Some(Arc::new(d))
        }
        Err(e) => {
            tracing::info!(error = %e, "scanu_flt not loaded: ETW mode (canaries via ETW, new programs scored right after start)");
            None
        }
    };
    let status = Arc::new(Status { device_id: cfg.device_id.clone(), cloud: uplink_cfg.is_some(), driver: driver.is_some() });

    // Telemetry sources → engine.
    let (etx, erx) = std::sync::mpsc::channel();
    let mut sources: Vec<Box<dyn EventSource>> = vec![Box::new(EtwSource::with_canaries(canary_paths)), Box::new(EventLogSource::default())];
    for s in sources.iter_mut() {
        if let Err(e) = s.start(etx.clone()) {
            tracing::error!(source = s.name(), error = %e, "event source failed to start");
        }
    }
    {
        let engine = engine.clone();
        let has_driver = driver.is_some();
        std::thread::Builder::new().name("ingest".into()).spawn(move || {
            let mut seen_images: HashMap<String, (u64, std::time::SystemTime)> = HashMap::new();
            for ev in erx {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let mut e = engine.lock().unwrap();
                if !has_driver {
                    if let RawEvent::ProcessStart { process, image_path, .. } = &ev {
                        // Score each distinct image version once (path + size + mtime).
                        let stamp = std::fs::metadata(image_path).ok().map(|m| (m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)));
                        if stamp.is_some() && seen_images.get(image_path) != stamp.as_ref() {
                            if e.on_exec_verdict(*process, image_path) == ExecDecision::Allow {
                                if seen_images.len() > 20_000 {
                                    seen_images.clear();
                                }
                                seen_images.insert(image_path.clone(), stamp.unwrap());
                            }
                        }
                    }
                }
                if let Err(err) = e.ingest(ev, t) {
                    tracing::error!(error = %err, "ingest failed");
                }
            }
        })?;
    }

    if let Some(d) = driver.clone() {
        let engine = engine.clone();
        std::thread::Builder::new().name("driver".into()).spawn(move || loop {
            match d.next() {
                Ok(DriverEvent::CanaryTrip { process, path, op, qpc, qpc_freq }) => {
                    let tripped_at = Instant::now() - qpc_elapsed(qpc, qpc_freq);
                    engine.lock().unwrap().canary_trip(process, "", &path, "kernel", op, tripped_at);
                }
                Ok(DriverEvent::PreExec { message_id, process, image }) => {
                    let (decision, _) = engine.lock().unwrap().pre_exec(process, &image);
                    let _ = d.reply_pre_exec(message_id, decision == ExecDecision::Block);
                }
                Ok(DriverEvent::Tamper { process, path }) => {
                    tracing::warn!(pid = process.pid, %path, "tamper attempt denied by driver");
                }
                Ok(DriverEvent::Heartbeat) => {}
                Err(e) => {
                    tracing::error!(error = %e, "driver port read failed");
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })?;
    }

    {
        let (engine, status) = (engine.clone(), status.clone());
        std::thread::Builder::new().name("desktop-pipe".into()).spawn(move || pipe_server(nrx, engine, status))?;
    }

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let uplink_task = uplink_cfg.map(|u| rt.spawn(uplink::run(engine.clone(), u, stop_rx)));
    tracing::info!(device = %status.device_id, cloud = status.cloud, driver = status.driver, version = env!("CARGO_PKG_VERSION"), "scanu-sensor running");
    let _ = stop.recv();
    let _ = stop_tx.send(true);
    if let Some(t) = uplink_task {
        let _ = rt.block_on(async { tokio::time::timeout(Duration::from_secs(5), t).await });
    }
    for s in sources.iter_mut() {
        s.stop();
    }
    Ok(())
}

/// Quick: per-user hot spots + ProgramData/Windows Temp. Full: every fixed drive.
fn scan_roots(data_dir: &Path) -> engine::scan::ScanRoots {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    let mut quick = vec![r"C:\ProgramData".to_string(), r"C:\Windows\Temp".to_string()];
    for home in user_homes() {
        for sub in ["Downloads", "Desktop", r"AppData\Local\Temp", r"AppData\Roaming", r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"] {
            quick.push(format!(r"{home}\{sub}"));
        }
    }
    let full = (b'A'..=b'Z')
        .map(|l| format!("{}:\\", l as char))
        .filter(|root| {
            let w: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) == DRIVE_FIXED }
        })
        .collect();
    engine::scan::ScanRoots { quick, full, exclude: vec![root().to_string_lossy().to_lowercase()] }
}

fn qpc_elapsed(qpc: u64, freq: u64) -> Duration {
    let mut now = 0i64;
    unsafe {
        let _ = windows::Win32::System::Performance::QueryPerformanceCounter(&mut now);
    }
    if freq == 0 || (now as u64) < qpc {
        return Duration::ZERO;
    }
    Duration::from_micros(((now as u64 - qpc) as u128 * 1_000_000 / freq as u128) as u64)
}

fn hide(path: &Path) {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
    let w: Vec<u16> = path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
}

fn notice_json(n: &LocalNotice) -> serde_json::Value {
    use serde_json::json;
    match n {
        LocalNotice::Frozen { alert_id, image_path, reason, elapsed_us } => {
            json!({"type":"frozen","alert_id":alert_id,"image":image_path,"reason":reason,"elapsed_us":elapsed_us})
        }
        LocalNotice::Blocked { image_path, reason } => json!({"type":"blocked","image":image_path,"reason":reason}),
        LocalNotice::Alert { alert_id, severity, summary } => {
            json!({"type":"alert","alert_id":alert_id,"severity":*severity as i32,"summary":summary})
        }
        LocalNotice::CommandExecuted { command_id, ok, reason } => {
            json!({"type":"command","command_id":command_id,"ok":ok,"reason":reason})
        }
        LocalNotice::Scan { scan_id, state, files_seen, findings } => json!({
            "type":"scan","scan_id":scan_id,"state":engine::engine::pb_scan_state_name(*state),
            "files_seen":files_seen,"findings":findings
        }),
        LocalNotice::Finding { alert_id, path, severity, summary, can_terminate, can_quarantine } => json!({
            "type":"finding","alert_id":alert_id,"path":path,"severity":*severity as i32,"summary":summary,
            "can_terminate":can_terminate,"can_quarantine":can_quarantine
        }),
    }
}

/// Requests a logged-in user may make locally. Read-only by design: anything
/// destructive must come as a cloud-signed, human-approved command.
fn handle_local(line: &str, engine: &Arc<Mutex<Engine>>, status: &Status) -> serde_json::Value {
    use serde_json::json;
    let Ok(req) = serde_json::from_str::<serde_json::Value>(line) else {
        return json!({"type":"error","error":"bad json"});
    };
    match req["cmd"].as_str() {
        Some("status") => json!({
            "type":"status","device_id":status.device_id,"cloud":status.cloud,"driver":status.driver,
            "scan_running":engine.lock().unwrap().scan_running(),"version":env!("CARGO_PKG_VERSION"),
        }),
        Some("scan") => {
            let scope = if req["scope"] == "full" { ScanScope::Full } else { ScanScope::Quick };
            match engine::scan::start_local(engine, scope) {
                Ok(id) => json!({"type":"scan_started","scan_id":id}),
                Err(e) => json!({"type":"error","error":e}),
            }
        }
        Some("findings") => {
            let list: Vec<_> = engine
                .lock()
                .unwrap()
                .local_findings()
                .into_iter()
                .map(|(id, t)| json!({
                    "alert_id": id, "path": t.path, "summary": t.summary, "severity": t.severity as i32,
                    "can_terminate": t.process.is_some(), "can_quarantine": !t.sha256.is_empty(),
                }))
                .collect();
            json!({"type":"findings","findings":list})
        }
        Some(action @ ("quarantine" | "terminate")) => {
            let id = req["alert_id"].as_str().unwrap_or_default();
            match engine.lock().unwrap().local_action(id, action) {
                Ok(msg) => json!({"type":"action","alert_id":id,"ok":true,"message":msg}),
                Err(e) => json!({"type":"action","alert_id":id,"ok":false,"message":e}),
            }
        }
        Some("cancel_scan") => {
            let ok = engine.lock().unwrap().cancel_scan(req["scan_id"].as_str().unwrap_or_default());
            json!({"type":"cancel","ok":ok})
        }
        _ => json!({"type":"error","error":"unsupported"}),
    }
}

/// One desktop client at a time; JSON lines both ways.
fn pipe_server(rx: std::sync::mpsc::Receiver<LocalNotice>, engine: Arc<Mutex<Engine>>, status: Arc<Status>) {
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT};

    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let name: Vec<u16> = PIPE.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None) }.is_err() {
        tracing::error!("pipe SDDL invalid; desktop link disabled");
        return;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let mut first = true;
    loop {
        let flags = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        first = false;
        let h = unsafe {
            CreateNamedPipeW(PCWSTR(name.as_ptr()), flags, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 64 * 1024, 64 * 1024, 0, Some(&sa))
        };
        if h.is_invalid() {
            tracing::error!("CreateNamedPipeW failed; retrying");
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let _ = unsafe { ConnectNamedPipe(h, None) };
        let file = unsafe { std::fs::File::from_raw_handle(h.0) };
        let Ok(reader) = file.try_clone() else { continue };
        let writer = Arc::new(Mutex::new(file));
        let connected = Arc::new(AtomicBool::new(true));
        {
            let (writer, connected, engine, status) = (writer.clone(), connected.clone(), engine.clone(), status.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(reader).lines() {
                    let Ok(line) = line else { break };
                    if line.len() > 4096 {
                        continue;
                    }
                    let reply = handle_local(&line, &engine, &status);
                    if writeln!(writer.lock().unwrap(), "{reply}").is_err() {
                        break;
                    }
                }
                connected.store(false, Ordering::Relaxed);
            });
        }
        while connected.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(n) => {
                    if writeln!(writer.lock().unwrap(), "{}", notice_json(&n)).is_err() {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}
