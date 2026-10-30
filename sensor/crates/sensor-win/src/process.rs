//! Process control. Suspend/resume use ntdll's NtSuspendProcess/NtResumeProcess
//! (stable since XP, used by every major EDR; not in the SDK metadata).

use crate::filetime_to_unix_ms;
use sensor_core::platform::{PlatformError, PlatformResult, ProcessControl};
use sensor_core::ProcessKey;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::core::PWSTR;
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> PlatformResult<Handle> {
    unsafe { OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map(Handle)
        .map_err(|e| PlatformError::Os(format!("OpenProcess({pid}): {e}")))
}

fn creation_ms(h: &Handle) -> Option<u64> {
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) }.ok()?;
    Some(filetime_to_unix_ms(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64))
}

/// (start time in unix ms, Win32 image path) straight from the OS. These are the
/// same values the PID-reuse guard checks, so keys built from them always match.
pub fn process_info(pid: u32) -> Option<(u64, String)> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let start = creation_ms(&h)?;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let image = unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }
        .ok()
        .map(|_| String::from_utf16_lossy(&buf[..len as usize]))
        .unwrap_or_default();
    Some((start, image))
}

#[derive(Default)]
pub struct WinProcessControl;

impl WinProcessControl {
    /// Opens the process and verifies it is still the same instance (PID reuse guard).
    fn open_checked(&self, p: ProcessKey, access: PROCESS_ACCESS_RIGHTS) -> PlatformResult<Handle> {
        let h = open(p.pid, access)?;
        match creation_ms(&h) {
            Some(t) if t == p.start_time_ms => Ok(h),
            Some(found) => Err(PlatformError::PidReused { pid: p.pid, expected: p.start_time_ms, found }),
            None => Err(PlatformError::NotFound(p)),
        }
    }
}

impl ProcessControl for WinProcessControl {
    fn start_time_ms(&self, pid: u32) -> Option<u64> {
        open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok().and_then(|h| creation_ms(&h))
    }

    fn suspend(&self, p: ProcessKey) -> PlatformResult<()> {
        let h = self.open_checked(p, PROCESS_SUSPEND_RESUME)?;
        let st = unsafe { NtSuspendProcess(h.0) };
        if st < 0 { Err(PlatformError::Os(format!("NtSuspendProcess: 0x{st:08x}"))) } else { Ok(()) }
    }

    fn resume(&self, p: ProcessKey) -> PlatformResult<()> {
        let h = self.open_checked(p, PROCESS_SUSPEND_RESUME)?;
        let st = unsafe { NtResumeProcess(h.0) };
        if st < 0 { Err(PlatformError::Os(format!("NtResumeProcess: 0x{st:08x}"))) } else { Ok(()) }
    }

    fn terminate(&self, p: ProcessKey) -> PlatformResult<()> {
        let h = self.open_checked(p, PROCESS_TERMINATE)?;
        unsafe { TerminateProcess(h.0, 0xC000_0022) }.map_err(|e| PlatformError::Os(format!("TerminateProcess: {e}")))
    }
}
