//! Client for the scanu_flt communication port (protocol: driver-win/scanu_flt/scanu_proto.h).

use crate::filetime_to_unix_ms;
use crate::paths::PathMap;
use sensor_core::ProcessKey;
use std::mem::size_of;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FilterSendMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};

pub const PROTO_VERSION: u32 = 1;
pub const MAX_PATH: usize = 520;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Notification {
    pub version: u32,
    pub kind: u32,
    pub pid: u32,
    pub parent_pid: u32,
    pub process_create_time: u64,
    pub qpc: u64,
    pub qpc_frequency: u64,
    pub op: u32,
    pub path_len: u32,
    pub path: [u16; MAX_PATH],
}

#[repr(C)]
struct InMessage {
    header: FILTER_MESSAGE_HEADER,
    body: Notification,
}

#[repr(C)]
struct ReplyMessage {
    header: FILTER_REPLY_HEADER,
    verdict: u32,
}

#[repr(C)]
struct Command {
    version: u32,
    kind: u32,
    path_len: u32,
    path: [u16; MAX_PATH],
}

pub enum DriverEvent {
    CanaryTrip { process: ProcessKey, path: String, op: &'static str, qpc: u64, qpc_freq: u64 },
    /// Must be answered with `reply_pre_exec(message_id, block)`.
    PreExec { message_id: u64, process: ProcessKey, image: String },
    Tamper { process: ProcessKey, path: String },
    Heartbeat,
}

pub struct DriverPort {
    port: HANDLE,
    pub paths: PathMap,
}

unsafe impl Send for DriverPort {}
unsafe impl Sync for DriverPort {}

fn op_name(op: u32) -> &'static str {
    match op {
        1 => "WRITE",
        2 => "RENAME",
        3 => "DELETE",
        4 => "SET_INFO",
        _ => "OPEN_FOR_WRITE",
    }
}

impl DriverPort {
    pub fn connect() -> windows::core::Result<Self> {
        let name: Vec<u16> = "\\ScanuPort".encode_utf16().chain(std::iter::once(0)).collect();
        let port = unsafe { FilterConnectCommunicationPort(PCWSTR(name.as_ptr()), 0, None, 0, None) }?;
        let me = Self { port, paths: PathMap::load() };
        me.command(1, "")?; // ScanuCmdRegisterSensor
        Ok(me)
    }

    fn command(&self, kind: u32, nt_path: &str) -> windows::core::Result<()> {
        let mut cmd = Command { version: PROTO_VERSION, kind, path_len: 0, path: [0; MAX_PATH] };
        for (i, c) in nt_path.encode_utf16().take(MAX_PATH).enumerate() {
            cmd.path[i] = c;
            cmd.path_len = i as u32 + 1;
        }
        let mut returned = 0u32;
        unsafe {
            FilterSendMessage(self.port, &cmd as *const _ as *const _, size_of::<Command>() as u32, None, 0, &mut returned)
        }
    }

    pub fn set_canaries(&self, dos_paths: &[String]) -> windows::core::Result<()> {
        self.command(2, "")?;
        for p in dos_paths {
            self.command(3, &self.paths.to_nt(p))?;
        }
        Ok(())
    }

    pub fn protect_prefix(&self, dos_path: &str) -> windows::core::Result<()> {
        self.command(4, &self.paths.to_nt(dos_path))
    }

    /// Blocks until the driver sends the next message.
    pub fn next(&self) -> windows::core::Result<DriverEvent> {
        let mut msg: Box<InMessage> = Box::new(unsafe { std::mem::zeroed() });
        unsafe { FilterGetMessage(self.port, &mut msg.header, size_of::<InMessage>() as u32, None) }?;
        let b = msg.body;
        let len = (b.path_len as usize).min(MAX_PATH);
        let path = self.paths.to_dos(&String::from_utf16_lossy(&b.path[..len]));
        let process = ProcessKey { pid: b.pid, start_time_ms: filetime_to_unix_ms(b.process_create_time) };
        Ok(match b.kind {
            1 => DriverEvent::CanaryTrip { process, path, op: op_name(b.op), qpc: b.qpc, qpc_freq: b.qpc_frequency },
            2 => DriverEvent::PreExec { message_id: msg.header.MessageId, process, image: path },
            3 => DriverEvent::Tamper { process, path },
            _ => DriverEvent::Heartbeat,
        })
    }

    pub fn reply_pre_exec(&self, message_id: u64, block: bool) -> windows::core::Result<()> {
        let reply = ReplyMessage {
            header: FILTER_REPLY_HEADER { Status: windows::Win32::Foundation::NTSTATUS(0), MessageId: message_id },
            verdict: block as u32,
        };
        unsafe { FilterReplyMessage(self.port, &reply.header, size_of::<ReplyMessage>() as u32) }
    }
}
