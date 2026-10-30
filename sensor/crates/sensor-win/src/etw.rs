//! User-mode ETW collectors (no driver needed): process, network (PID-bound),
//! DNS, file, and PowerShell script blocks.

use crate::filetime_to_unix_ms;
use crate::paths::PathMap;
use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use sensor_core::event::Direction;
use sensor_core::platform::{EventSource, PlatformError, PlatformResult};
use sensor_core::{FileOp, ProcessKey, RawEvent};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const POWERSHELL: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";

/// pid → (start_time_ms, image) learned from process-start events, so later
/// events can be keyed reuse-safely.
type ProcTable = Arc<Mutex<HashMap<u32, (u64, String)>>>;

/// Lower-cased DOS paths of the deployed canaries. Writes are tracked only for
/// these (full write telemetry would cost far more than it's worth).
pub type CanaryPaths = Arc<RwLock<HashSet<String>>>;

pub struct EtwSource {
    procs: ProcTable,
    canaries: CanaryPaths,
    trace: Option<UserTrace>,
}

impl Default for EtwSource {
    fn default() -> Self {
        Self { procs: Arc::new(Mutex::new(HashMap::new())), canaries: Arc::default(), trace: None }
    }
}

impl EtwSource {
    pub fn with_canaries(canaries: CanaryPaths) -> Self {
        Self { canaries, ..Self::default() }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Reuse-safe key for `pid`. Processes that predate the sensor (or whose start
/// event we missed) are looked up from the OS once and cached.
fn key(procs: &ProcTable, pid: u32) -> (ProcessKey, String) {
    if let Some((start, image)) = procs.lock().unwrap().get(&pid).cloned() {
        return (ProcessKey { pid, start_time_ms: start }, image);
    }
    let (start, image) = crate::process::process_info(pid).unwrap_or((0, String::new()));
    if start != 0 {
        let mut t = procs.lock().unwrap();
        if t.len() > 50_000 {
            t.clear();
        }
        t.insert(pid, (start, image.clone()));
    }
    (ProcessKey { pid, start_time_ms: start }, image)
}

impl EventSource for EtwSource {
    fn name(&self) -> &'static str {
        "etw"
    }

    fn start(&mut self, tx: Sender<RawEvent>) -> PlatformResult<()> {
        // Kernel providers report NT device paths; the engine needs drive-letter paths.
        let paths = Arc::new(PathMap::load());
        let (p1, t1, m1) = (self.procs.clone(), tx.clone(), paths.clone());
        let process = Provider::by_guid(KERNEL_PROCESS)
            .any(0x10) // WINEVENT_KEYWORD_PROCESS
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                match r.event_id() {
                    1 => {
                        let pid: u32 = p.try_parse("ProcessID").unwrap_or(0);
                        let ppid: u32 = p.try_parse("ParentProcessID").unwrap_or(0);
                        // Prefer the OS's own values: they are what the PID-reuse guard compares
                        // against. ETW's CreateTime/ImageName are the fallback (process already gone).
                        let (start, image) = crate::process::process_info(pid).unwrap_or_else(|| {
                            let ft = p.try_parse::<u64>("CreateTime").unwrap_or(0);
                            (filetime_to_unix_ms(ft), m1.to_dos(&p.try_parse::<String>("ImageName").unwrap_or_default()))
                        });
                        let image = if image.is_empty() { m1.to_dos(&p.try_parse::<String>("ImageName").unwrap_or_default()) } else { image };
                        let parent = key(&p1, ppid).0;
                        p1.lock().unwrap().insert(pid, (start, image.clone()));
                        let _ = t1.send(RawEvent::ProcessStart {
                            process: ProcessKey { pid, start_time_ms: start },
                            parent: (parent.start_time_ms != 0).then_some(parent),
                            image_path: image,
                            cmdline: String::new(), // filled from Security 4688 when enabled
                            user: String::new(),
                            sha256: None,
                        });
                    }
                    2 => {
                        let pid: u32 = p.try_parse("ProcessID").unwrap_or(0);
                        let (k, _) = key(&p1, pid);
                        let _ = t1.send(RawEvent::ProcessStop { process: k, exit_code: p.try_parse("ExitCode").unwrap_or(0) });
                        p1.lock().unwrap().remove(&pid);
                    }
                    _ => {}
                }
            })
            .build();

        let (p2, t2) = (self.procs.clone(), tx.clone());
        let network = Provider::by_guid(KERNEL_NETWORK)
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                // 12/15: TCPv4/v6 connect; 11/14: accept. Only IPv4 parsed in MVP.
                if !matches!(r.event_id(), 12 | 11) {
                    return;
                }
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let pid: u32 = p.try_parse("PID").unwrap_or(0);
                let (k, image) = key(&p2, pid);
                let daddr: u32 = p.try_parse("daddr").unwrap_or(0);
                let saddr: u32 = p.try_parse("saddr").unwrap_or(0);
                let ip = |v: u32| IpAddr::V4(Ipv4Addr::from(u32::from_be(v))).to_string();
                let _ = t2.send(RawEvent::Network {
                    process: k,
                    image_path: image,
                    direction: if r.event_id() == 12 { Direction::Outbound } else { Direction::Inbound },
                    protocol: "tcp".into(),
                    local_addr: ip(saddr),
                    local_port: u16::from_be(p.try_parse("sport").unwrap_or(0)),
                    remote_addr: ip(daddr),
                    remote_port: u16::from_be(p.try_parse("dport").unwrap_or(0)),
                    bytes_out: p.try_parse::<u32>("size").unwrap_or(0) as u64,
                    bytes_in: 0,
                });
            })
            .build();

        let (p3, t3) = (self.procs.clone(), tx.clone());
        let dns = Provider::by_guid(DNS_CLIENT)
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                if r.event_id() != 3008 {
                    return;
                }
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let (k, image) = key(&p3, r.process_id());
                let answers: String = p.try_parse("QueryResults").unwrap_or_default();
                let _ = t3.send(RawEvent::Dns {
                    process: k,
                    image_path: image,
                    query: p.try_parse("QueryName").unwrap_or_default(),
                    answers: answers.split(';').filter(|s| !s.is_empty()).map(|s| s.trim_start_matches("::ffff:").to_string()).collect(),
                });
            })
            .build();

        let (p4, t4, m4, canaries) = (self.procs.clone(), tx.clone(), paths.clone(), self.canaries.clone());
        // FileObject → canary path, learned from opens of canary files only.
        let open_canaries: Arc<Mutex<HashMap<usize, String>>> = Arc::default();
        let file = Provider::by_guid(KERNEL_FILE)
            .any(0x80 | 0x200 | 0x400 | 0x800 | 0x1000) // CREATE | WRITE | DELETE_PATH | RENAME_PATH | CREATE_NEW_FILE
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                // 12 Create(open) · 16 Write · 26 DeletePath · 27 RenamePath · 30 CreateNewFile
                let id = r.event_id();
                if !matches!(id, 12 | 16 | 26 | 27 | 30) {
                    return;
                }
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let file_object = p.try_parse::<Pointer>("FileObject").map(|x| *x).unwrap_or(0);
                let (path, op) = match id {
                    // Opens are not telemetry (far too many); remember canary handles for writes.
                    12 => {
                        let path = m4.to_dos(&p.try_parse::<String>("FileName").unwrap_or_default());
                        if file_object != 0 && canaries.read().unwrap().contains(&path.to_lowercase()) {
                            let mut m = open_canaries.lock().unwrap();
                            if m.len() > 4_096 {
                                m.clear();
                            }
                            m.insert(file_object, path);
                        }
                        return;
                    }
                    16 => match open_canaries.lock().unwrap().get(&file_object) {
                        Some(path) => (path.clone(), FileOp::Write),
                        None => return,
                    },
                    26 => (m4.to_dos(&p.try_parse::<String>("FilePath").unwrap_or_default()), FileOp::Delete),
                    27 => (m4.to_dos(&p.try_parse::<String>("FilePath").unwrap_or_default()), FileOp::Rename),
                    _ => (m4.to_dos(&p.try_parse::<String>("FileName").unwrap_or_default()), FileOp::Create),
                };
                if path.is_empty() {
                    return;
                }
                let (k, image) = key(&p4, r.process_id());
                let _ = t4.send(RawEvent::File { process: k, image_path: image, path, op, new_path: None });
            })
            .build();

        let (p5, t5) = (self.procs.clone(), tx);
        let ps = Provider::by_guid(POWERSHELL)
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                if r.event_id() != 4104 {
                    return;
                }
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let (k, image) = key(&p5, r.process_id());
                let _ = t5.send(RawEvent::Script {
                    process: k,
                    image_path: image,
                    engine: "PowerShell".into(),
                    content: p.try_parse("ScriptBlockText").unwrap_or_default(),
                });
            })
            .build();

        let trace = UserTrace::new()
            .named(String::from("ScanuSensor"))
            .enable(process)
            .enable(network)
            .enable(dns)
            .enable(file)
            .enable(ps)
            .start_and_process()
            .map_err(|e| PlatformError::Os(format!("ETW: {e:?}")))?;
        self.trace = Some(trace);
        let _ = now_ms;
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}
