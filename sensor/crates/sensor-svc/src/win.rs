use ed25519_dalek::pkcs8::DecodePublicKey;
use engine::uplink::{self, UplinkConfig};
use engine::{Engine, EngineConfig, ExecDecision, LocalNotice};
use sensor_core::platform::EventSource;
use sensor_win::driver::{DriverEvent, DriverPort};
use sensor_win::etw::EtwSource;
use sensor_win::eventlog::EventLogSource;
use sensor_win::keys::DpapiKey;
use sensor_win::process::WinProcessControl;
use sensor_win::wfp::WinNetworkControl;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const SERVICE_NAME: &str = "ScanuSensor";
const CONFIG: &str = r"C:\ProgramData\Scanu\sensor.json";
const PIPE: &str = r"\\.\pipe\scanu-desktop";
/// SYSTEM full control; interactive users read/write (they receive notices and
/// may send prompt choices, which still need a cloud-signed command to act).
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;IU)";

#[derive(Deserialize)]
struct Config {
    device_id: String,
    gateway: String,
    #[serde(default = "default_pki")]
    pki_dir: PathBuf,
    #[serde(default = "default_data")]
    data_dir: PathBuf,
    #[serde(default)]
    canary_dirs: Vec<String>,
    #[serde(default)]
    bloom_path: Option<PathBuf>,
}

fn default_pki() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\Scanu\pki")
}

fn default_data() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\Scanu\data")
}

define_windows_service!(ffi_service_main, service_main);

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    if std::env::args().any(|a| a == "--console") {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = ctrlc_fallback(tx);
        if let Err(e) = run(rx) {
            tracing::error!(error = %e, "sensor failed");
        }
    } else if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("not started by the SCM ({e}); use --console to run interactively");
    }
}

fn ctrlc_fallback(tx: std::sync::mpsc::Sender<()>) -> std::io::Result<()> {
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s); // Enter stops console mode
        let _ = tx.send(());
    });
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handler = move |ev| match ev {
        ServiceControl::Stop => {
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
            controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP } else { ServiceControlAccept::empty() },
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

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn run(stop: std::sync::mpsc::Receiver<()>) -> R<()> {
    let cfg: Config = serde_json::from_slice(&std::fs::read(CONFIG)?)?;
    std::fs::create_dir_all(&cfg.data_dir)?;

    let mut keys = HashMap::new();
    let pem = std::fs::read_to_string(cfg.pki_dir.join("cmd-signing.pub.pem"))?;
    let key_id = std::fs::read_to_string(cfg.pki_dir.join("cmd-signing.key_id"))?.trim().to_string();
    keys.insert(key_id, ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)?);

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

    // Canaries: deploy, hide, and hand to the driver.
    let dirs: Vec<&str> = cfg.canary_dirs.iter().map(String::as_str).collect();
    let specs = eng.deploy_canaries(&dirs)?;
    for s in &specs {
        hide(&s.path);
    }
    let engine = Arc::new(Mutex::new(eng));

    let driver = match DriverPort::connect() {
        Ok(d) => {
            d.set_canaries(&specs.iter().map(|s| s.path.to_string_lossy().into_owned()).collect::<Vec<_>>())?;
            d.protect_prefix(&cfg.data_dir.to_string_lossy())?;
            d.protect_prefix(r"C:\Program Files\Scanu")?;
            tracing::info!("minifilter connected: kernel canary + pre-exec + self-protection active");
            Some(Arc::new(d))
        }
        Err(e) => {
            tracing::warn!(error = %e, "scanu_flt not loaded; ETW-only mode (no kernel I/O deny, no pre-exec gate)");
            None
        }
    };

    // Telemetry sources → engine.
    let (etx, erx) = std::sync::mpsc::channel();
    let mut sources: Vec<Box<dyn EventSource>> = vec![Box::new(EtwSource::default()), Box::new(EventLogSource::default())];
    for s in sources.iter_mut() {
        if let Err(e) = s.start(etx.clone()) {
            tracing::error!(source = s.name(), error = %e, "event source failed to start");
        }
    }
    {
        let engine = engine.clone();
        std::thread::Builder::new().name("ingest".into()).spawn(move || {
            for ev in erx {
                let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                if let Err(e) = engine.lock().unwrap().ingest(ev, t) {
                    tracing::error!(error = %e, "ingest failed");
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

    std::thread::Builder::new().name("desktop-pipe".into()).spawn(move || pipe_server(nrx))?;

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let pki = cfg.pki_dir.clone();
    let ucfg = UplinkConfig {
        endpoint: cfg.gateway.clone(),
        domain: "gateway".into(),
        ca_pem: std::fs::read(pki.join("ca.pem"))?,
        cert_pem: std::fs::read(pki.join("device.pem"))?,
        key_pem: std::fs::read(pki.join("device.key"))?,
        os: "Windows".into(),
        batch_size: 500,
        flush_every: Duration::from_secs(2),
    };
    let uplink_task = rt.spawn(uplink::run(engine.clone(), ucfg, stop_rx));
    tracing::info!(device = %cfg.device_id, "scanu-sensor running");
    let _ = stop.recv();
    let _ = stop_tx.send(true);
    let _ = rt.block_on(async { tokio::time::timeout(Duration::from_secs(5), uplink_task).await });
    for s in sources.iter_mut() {
        s.stop();
    }
    Ok(())
}

/// Quick: per-user hot spots + ProgramData/Windows Temp. Full: every fixed drive.
fn scan_roots(data_dir: &std::path::Path) -> engine::scan::ScanRoots {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    let mut quick = vec![r"C:\ProgramData".to_string(), r"C:\Windows\Temp".to_string()];
    if let Ok(users) = std::fs::read_dir(r"C:\Users") {
        for u in users.flatten().filter(|u| u.file_type().map(|t| t.is_dir()).unwrap_or(false)) {
            let home = u.path().to_string_lossy().into_owned();
            for sub in ["Downloads", "Desktop", r"AppData\Local\Temp", r"AppData\Roaming", r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"] {
                quick.push(format!(r"{home}\{sub}"));
            }
        }
    }
    let full = (b'A'..=b'Z')
        .map(|l| format!("{}:\\", l as char))
        .filter(|root| {
            let w: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) == DRIVE_FIXED }
        })
        .collect();
    engine::scan::ScanRoots { quick, full, exclude: vec![data_dir.to_string_lossy().to_lowercase()] }
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

fn hide(path: &std::path::Path) {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};
    let w: Vec<u16> = path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let _ = SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
}

/// One desktop client at a time; notices are JSON lines.
fn pipe_server(rx: std::sync::mpsc::Receiver<LocalNotice>) {
    use std::os::windows::io::FromRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_OUTBOUND};
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT};

    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let name: Vec<u16> = PIPE.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None) }.is_err() {
        tracing::error!("pipe SDDL invalid; desktop notifications disabled");
        return;
    }
    let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
    let mut first = true;
    loop {
        let flags = if first { PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_OUTBOUND };
        first = false;
        let h = unsafe {
            CreateNamedPipeW(PCWSTR(name.as_ptr()), flags, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 64 * 1024, 0, 0, Some(&sa))
        };
        if h.is_invalid() {
            tracing::error!("CreateNamedPipeW failed");
            return;
        }
        let _ = unsafe { ConnectNamedPipe(h, None) };
        let mut file = unsafe { std::fs::File::from_raw_handle(h.0) };
        for n in rx.iter() {
            let line = match &n {
                LocalNotice::Frozen { alert_id, image_path, reason, elapsed_us } => serde_json::json!({"type":"frozen","alert_id":alert_id,"image":image_path,"reason":reason,"elapsed_us":elapsed_us}),
                LocalNotice::Blocked { image_path, reason } => serde_json::json!({"type":"blocked","image":image_path,"reason":reason}),
                LocalNotice::Alert { alert_id, severity, summary } => serde_json::json!({"type":"alert","alert_id":alert_id,"severity":*severity as i32,"summary":summary}),
                LocalNotice::CommandExecuted { command_id, ok, reason } => serde_json::json!({"type":"command","command_id":command_id,"ok":ok,"reason":reason}),
                LocalNotice::Scan { scan_id, state, files_seen, findings } => serde_json::json!({"type":"scan","scan_id":scan_id,"state":engine::engine::pb_scan_state_name(*state),"files_seen":files_seen,"findings":findings}),
            };
            if writeln!(file, "{line}").is_err() {
                break; // client went away; wait for the next one
            }
        }
    }
}
