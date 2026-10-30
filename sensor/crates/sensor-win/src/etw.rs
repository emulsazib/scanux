//! User-mode ETW collectors (no driver needed): process, network (PID-bound),
//! DNS, file, and PowerShell script blocks.

use crate::filetime_to_unix_ms;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use sensor_core::event::Direction;
use sensor_core::platform::{EventSource, PlatformError, PlatformResult};
use sensor_core::{FileOp, ProcessKey, RawEvent};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const POWERSHELL: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";

/// pid → (start_time_ms, image) learned from process-start events, so later
/// events can be keyed reuse-safely.
type ProcTable = Arc<Mutex<HashMap<u32, (u64, String)>>>;

pub struct EtwSource {
    procs: ProcTable,
    trace: Option<UserTrace>,
}

impl Default for EtwSource {
    fn default() -> Self {
        Self { procs: Arc::new(Mutex::new(HashMap::new())), trace: None }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn key(procs: &ProcTable, pid: u32) -> (ProcessKey, String) {
    let t = procs.lock().unwrap();
    let (start, image) = t.get(&pid).cloned().unwrap_or((0, String::new()));
    (ProcessKey { pid, start_time_ms: start }, image)
}

impl EventSource for EtwSource {
    fn name(&self) -> &'static str {
        "etw"
    }

    fn start(&mut self, tx: Sender<RawEvent>) -> PlatformResult<()> {
        let (p1, t1) = (self.procs.clone(), tx.clone());
        let process = Provider::by_guid(KERNEL_PROCESS)
            .any(0x10) // WINEVENT_KEYWORD_PROCESS
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                match r.event_id() {
                    1 => {
                        let pid: u32 = p.try_parse("ProcessID").unwrap_or(0);
                        let ppid: u32 = p.try_parse("ParentProcessID").unwrap_or(0);
                        let image: String = p.try_parse("ImageName").unwrap_or_default();
                        let ft: u64 = p.try_parse::<u64>("CreateTime").unwrap_or(0);
                        let start = filetime_to_unix_ms(ft);
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

        let (p4, t4) = (self.procs.clone(), tx.clone());
        let file = Provider::by_guid(KERNEL_FILE)
            .any(0x10 | 0x20 | 0x400 | 0x800 | 0x1000) // FILENAME | FILEIO | CREATE | DELETE_PATH | RENAME_PATH
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                // 12 Create, 16 Write (via FileObject→name cache in M2), 26 DeletePath, 27 RenamePath
                let op = match r.event_id() {
                    12 => FileOp::Create,
                    26 => FileOp::Delete,
                    27 => FileOp::Rename,
                    _ => return,
                };
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let (k, image) = key(&p4, r.process_id());
                let path: String = p.try_parse("FileName").or_else(|_| p.try_parse("FilePath")).unwrap_or_default();
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
