//! Security / System event log subscription (auth, privilege use, process
//! creation with command line, service installs, account creation).

use sensor_core::platform::{EventSource, PlatformError, PlatformResult};
use sensor_core::RawEvent;
use std::sync::mpsc::Sender;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents, EVT_HANDLE,
    EVT_SUBSCRIBE_NOTIFY_ACTION, EvtSubscribeActionDeliver,
};

const QUERY: &str = "<QueryList>\
  <Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4720)]]</Select></Query>\
  <Query Id='1' Path='System'><Select Path='System'>*[System[(EventID=7045)]]</Select></Query>\
</QueryList>";

pub struct EventLogSource {
    sub: Option<EVT_HANDLE>,
    ctx: Option<Box<Sender<RawEvent>>>,
}

impl Default for EventLogSource {
    fn default() -> Self {
        Self { sub: None, ctx: None }
    }
}

unsafe impl Send for EventLogSource {}

fn field<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let tag = format!("<Data Name='{name}'>");
    let start = xml.find(&tag)? + tag.len();
    let end = xml[start..].find("</Data>")? + start;
    Some(&xml[start..end])
}

fn event_id(xml: &str) -> u32 {
    xml.find("<EventID")
        .and_then(|i| xml[i..].find('>').map(|j| i + j + 1))
        .and_then(|s| xml[s..].find('<').map(|e| &xml[s..s + e]))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Pure XML → RawEvent mapping (unit-testable).
pub fn map_xml(xml: &str) -> Option<RawEvent> {
    let id = event_id(xml);
    match id {
        4624 | 4625 => Some(RawEvent::Auth {
            user: field(xml, "TargetUserName").unwrap_or_default().to_string(),
            logon_type: field(xml, "LogonType").and_then(|v| v.parse().ok()).unwrap_or(0),
            success: id == 4624,
            source_addr: field(xml, "IpAddress").filter(|v| *v != "-").map(str::to_string),
            event_code: id,
        }),
        4672 | 4720 => Some(RawEvent::Auth {
            user: field(xml, "SubjectUserName").unwrap_or_default().to_string(),
            logon_type: 0,
            success: true,
            source_addr: None,
            event_code: id,
        }),
        4697 | 7045 => Some(RawEvent::Persistence {
            process: sensor_core::ProcessKey { pid: 0, start_time_ms: 0 },
            image_path: String::new(),
            mechanism: "service_install".into(),
            location: field(xml, "ServiceName").unwrap_or_default().to_string(),
            value: field(xml, "ImagePath").or_else(|| field(xml, "ServiceFileName")).unwrap_or_default().to_string(),
        }),
        _ => None,
    }
}

unsafe extern "system" fn callback(action: EVT_SUBSCRIBE_NOTIFY_ACTION, ctx: *const core::ffi::c_void, ev: EVT_HANDLE) -> u32 {
    if action != EvtSubscribeActionDeliver {
        return 0;
    }
    let tx = unsafe { &*(ctx as *const Sender<RawEvent>) };
    let mut buf = vec![0u16; 16 * 1024];
    let (mut used, mut props) = (0u32, 0u32);
    let ok = unsafe {
        EvtRender(None, ev, EvtRenderEventXml.0, (buf.len() * 2) as u32, Some(buf.as_mut_ptr() as *mut _), &mut used, &mut props)
    };
    if ok.is_ok() {
        let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).saturating_sub(1)]);
        if let Some(e) = map_xml(&xml) {
            let _ = tx.send(e);
        }
    }
    0
}

impl EventSource for EventLogSource {
    fn name(&self) -> &'static str {
        "eventlog"
    }

    fn start(&mut self, tx: Sender<RawEvent>) -> PlatformResult<()> {
        let ctx = Box::new(tx);
        let q: Vec<u16> = QUERY.encode_utf16().chain(std::iter::once(0)).collect();
        let sub = unsafe {
            EvtSubscribe(
                None,
                None,
                PCWSTR::null(),
                PCWSTR(q.as_ptr()),
                None,
                Some(&*ctx as *const Sender<RawEvent> as *const _),
                Some(callback),
                EvtSubscribeToFutureEvents.0,
            )
        }
        .map_err(|e| PlatformError::Os(format!("EvtSubscribe: {e}")))?;
        self.sub = Some(sub);
        self.ctx = Some(ctx);
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(s) = self.sub.take() {
            unsafe {
                let _ = EvtClose(s);
            }
        }
        self.ctx = None;
    }
}
