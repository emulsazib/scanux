use serde::{Deserialize, Serialize};

/// Reuse-safe process identity: a PID alone is recycled by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    Create,
    Write,
    Rename,
    Delete,
    SetInfo,
    Read,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Telemetry as produced by a platform collector, before OCSF normalization.
/// String fields are attacker-influenced and must never be interpreted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RawEvent {
    ProcessStart {
        process: ProcessKey,
        parent: Option<ProcessKey>,
        image_path: String,
        cmdline: String,
        user: String,
        sha256: Option<String>,
    },
    ProcessStop {
        process: ProcessKey,
        exit_code: i32,
    },
    File {
        process: ProcessKey,
        image_path: String,
        path: String,
        op: FileOp,
        new_path: Option<String>,
    },
    Network {
        process: ProcessKey,
        image_path: String,
        direction: Direction,
        protocol: String,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        bytes_out: u64,
        bytes_in: u64,
    },
    Dns {
        process: ProcessKey,
        image_path: String,
        query: String,
        answers: Vec<String>,
    },
    Script {
        process: ProcessKey,
        image_path: String,
        engine: String,
        content: String,
    },
    Auth {
        user: String,
        logon_type: u32,
        success: bool,
        source_addr: Option<String>,
        event_code: u32,
    },
    Persistence {
        process: ProcessKey,
        image_path: String,
        mechanism: String,
        location: String,
        value: String,
    },
}

impl RawEvent {
    pub fn process(&self) -> Option<ProcessKey> {
        match self {
            RawEvent::ProcessStart { process, .. }
            | RawEvent::ProcessStop { process, .. }
            | RawEvent::File { process, .. }
            | RawEvent::Network { process, .. }
            | RawEvent::Dns { process, .. }
            | RawEvent::Script { process, .. }
            | RawEvent::Persistence { process, .. } => Some(*process),
            RawEvent::Auth { .. } => None,
        }
    }
}
