//! RawEvent → OCSF JSON (version in schemas/ocsf/VERSION). Scanu-specific
//! attributes go under `unmapped.scanu` (schemas/ocsf/extensions/scanu.json).

use crate::event::{Direction, FileOp, ProcessKey, RawEvent};
use crate::privacy::{scrub_secrets, truncate, Pseudonymizer, CMDLINE_MAX, SCRIPT_PREVIEW_MAX};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const OCSF_VERSION: &str = "1.4.0";

pub const CLASS_FILE: u32 = 1001;
pub const CLASS_PROCESS: u32 = 1007;
pub const CLASS_AUTH: u32 = 3002;
pub const CLASS_NETWORK: u32 = 4001;
pub const CLASS_DNS: u32 = 4003;

pub struct DeviceInfo {
    pub device_id: String,
    pub os_name: String,
    pub sensor_version: String,
}

pub struct Normalizer {
    pub device: DeviceInfo,
    pub pseudo: Pseudonymizer,
}

fn category(class_uid: u32) -> u32 {
    class_uid / 1000
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

impl Normalizer {
    fn base(&self, class_uid: u32, activity_id: u32, time_ms: u64) -> Value {
        json!({
            "class_uid": class_uid,
            "category_uid": category(class_uid),
            "activity_id": activity_id,
            "type_uid": class_uid as u64 * 100 + activity_id as u64,
            "severity_id": 1,
            "time": time_ms,
            "metadata": {
                "version": OCSF_VERSION,
                "product": { "name": "Scanu Sensor", "vendor_name": "Scanu", "version": self.device.sensor_version },
            },
            "device": { "uid": self.device.device_id, "os": { "name": self.device.os_name } },
        })
    }

    fn process_obj(&self, p: ProcessKey, image_path: &str) -> Value {
        let path = self.pseudo.path(image_path);
        json!({
            "pid": p.pid,
            "created_time": p.start_time_ms,
            "file": { "path": path, "name": file_name(image_path) },
        })
    }

    /// Returns `(class_uid, ocsf_event)`.
    pub fn normalize(&self, ev: &RawEvent, time_ms: u64) -> (u32, Value) {
        match ev {
            RawEvent::ProcessStart { process, parent, image_path, cmdline, user, sha256 } => {
                let mut v = self.base(CLASS_PROCESS, 1, time_ms);
                let mut proc_ = self.process_obj(*process, image_path);
                proc_["cmd_line"] = json!(scrub_secrets(cmdline, CMDLINE_MAX));
                if let Some(h) = sha256 {
                    proc_["file"]["hashes"] = json!([{ "algorithm_id": 3, "value": h }]);
                }
                if let Some(pp) = parent {
                    proc_["parent_process"] = json!({ "pid": pp.pid, "created_time": pp.start_time_ms });
                    v["actor"] = json!({ "process": { "pid": pp.pid, "created_time": pp.start_time_ms } });
                }
                proc_["user"] = json!({ "name": self.pseudo.user(user) });
                v["process"] = proc_;
                (CLASS_PROCESS, v)
            }
            RawEvent::ProcessStop { process, exit_code } => {
                let mut v = self.base(CLASS_PROCESS, 2, time_ms);
                v["process"] = json!({ "pid": process.pid, "created_time": process.start_time_ms });
                v["exit_code"] = json!(exit_code);
                (CLASS_PROCESS, v)
            }
            RawEvent::File { process, image_path, path, op, new_path } => {
                let activity = match op {
                    FileOp::Create => 1,
                    FileOp::Read => 2,
                    FileOp::Write => 3,
                    FileOp::Delete => 4,
                    FileOp::Rename => 5,
                    FileOp::SetInfo => 6,
                };
                let mut v = self.base(CLASS_FILE, activity, time_ms);
                v["actor"] = json!({ "process": self.process_obj(*process, image_path) });
                v["file"] = json!({ "path": self.pseudo.path(path), "name": file_name(path) });
                if let Some(np) = new_path {
                    v["file_result"] = json!({ "path": self.pseudo.path(np), "name": file_name(np) });
                }
                (CLASS_FILE, v)
            }
            RawEvent::Network {
                process, image_path, direction, protocol, local_addr, local_port,
                remote_addr, remote_port, bytes_out, bytes_in,
            } => {
                let mut v = self.base(CLASS_NETWORK, 1, time_ms);
                v["actor"] = json!({ "process": self.process_obj(*process, image_path) });
                v["src_endpoint"] = json!({ "ip": local_addr, "port": local_port });
                v["dst_endpoint"] = json!({ "ip": remote_addr, "port": remote_port });
                v["connection_info"] = json!({
                    "protocol_name": protocol,
                    "direction_id": match direction { Direction::Inbound => 1, Direction::Outbound => 2 },
                });
                v["traffic"] = json!({ "bytes_out": bytes_out, "bytes_in": bytes_in });
                (CLASS_NETWORK, v)
            }
            RawEvent::Dns { process, image_path, query, answers } => {
                let mut v = self.base(CLASS_DNS, 1, time_ms);
                v["actor"] = json!({ "process": self.process_obj(*process, image_path) });
                v["query"] = json!({ "hostname": truncate(query, 255) });
                v["answers"] = Value::Array(answers.iter().map(|a| json!({ "rdata": a })).collect());
                (CLASS_DNS, v)
            }
            RawEvent::Script { process, image_path, engine, content } => {
                // OCSF 1.4 has no script-content class; keep it as process "Other".
                let mut v = self.base(CLASS_PROCESS, 99, time_ms);
                v["process"] = self.process_obj(*process, image_path);
                v["unmapped"] = json!({ "scanu": { "script": {
                    "engine": engine,
                    "sha256": hex::encode(Sha256::digest(content.as_bytes())),
                    "preview": scrub_secrets(content, SCRIPT_PREVIEW_MAX),
                }}});
                (CLASS_PROCESS, v)
            }
            RawEvent::Auth { user, logon_type, success, source_addr, event_code } => {
                let mut v = self.base(CLASS_AUTH, 1, time_ms);
                v["user"] = json!({ "name": self.pseudo.user(user) });
                v["status_id"] = json!(if *success { 1 } else { 2 });
                v["logon_type_id"] = json!(logon_type);
                if let Some(ip) = source_addr {
                    v["src_endpoint"] = json!({ "ip": ip });
                }
                v["unmapped"] = json!({ "scanu": { "event_code": event_code } });
                (CLASS_AUTH, v)
            }
            RawEvent::Persistence { process, image_path, mechanism, location, value } => {
                let mut v = self.base(CLASS_PROCESS, 99, time_ms);
                v["process"] = self.process_obj(*process, image_path);
                v["unmapped"] = json!({ "scanu": { "persistence": {
                    "mechanism": mechanism,
                    "location": self.pseudo.path(location),
                    "value": scrub_secrets(value, CMDLINE_MAX),
                }}});
                (CLASS_PROCESS, v)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n() -> Normalizer {
        Normalizer {
            device: DeviceInfo { device_id: "dev-1".into(), os_name: "Windows".into(), sensor_version: "0.1.0".into() },
            pseudo: Pseudonymizer::new([1; 16]),
        }
    }

    #[test]
    fn process_start_maps_to_1007_launch() {
        let ev = RawEvent::ProcessStart {
            process: ProcessKey { pid: 10, start_time_ms: 5 },
            parent: Some(ProcessKey { pid: 4, start_time_ms: 1 }),
            image_path: r"C:\Users\Bob\Downloads\x.exe".into(),
            cmdline: "x.exe --password=s3cret".into(),
            user: "Bob".into(),
            sha256: Some("ab".repeat(32)),
        };
        let (cls, v) = n().normalize(&ev, 1000);
        assert_eq!(cls, 1007);
        assert_eq!(v["type_uid"], 100701);
        assert_eq!(v["process"]["parent_process"]["pid"], 4);
        let s = v.to_string();
        assert!(!s.contains("Bob") && !s.contains("s3cret"), "{s}");
    }

    #[test]
    fn dns_and_network_carry_actor_pid() {
        let p = ProcessKey { pid: 9, start_time_ms: 2 };
        let (cls, v) = n().normalize(
            &RawEvent::Dns { process: p, image_path: "a.exe".into(), query: "x.example".into(), answers: vec!["1.2.3.4".into()] },
            1,
        );
        assert_eq!((cls, v["actor"]["process"]["pid"].as_u64()), (4003, Some(9)));
        let (cls, v) = n().normalize(
            &RawEvent::Network {
                process: p, image_path: "a.exe".into(), direction: Direction::Outbound, protocol: "tcp".into(),
                local_addr: "10.0.0.2".into(), local_port: 5000, remote_addr: "203.0.113.9".into(),
                remote_port: 443, bytes_out: 10, bytes_in: 20,
            },
            1,
        );
        assert_eq!((cls, v["connection_info"]["direction_id"].as_u64()), (4001, Some(2)));
    }
}
