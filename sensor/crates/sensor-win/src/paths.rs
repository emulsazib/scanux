//! NT device paths (what the minifilter sees) <-> DOS paths (what users and
//! ETW mostly see). Built once from QueryDosDeviceW and refreshed on demand.

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

pub struct PathMap {
    /// ("C:", "\Device\HarddiskVolume3")
    drives: Vec<(String, String)>,
}

impl PathMap {
    pub fn load() -> Self {
        let mask = unsafe { GetLogicalDrives() };
        let mut drives = Vec::new();
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = format!("{}:", (b'A' + i as u8) as char);
            let name: Vec<u16> = letter.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 512];
            let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
                drives.push((letter, String::from_utf16_lossy(&buf[..end])));
            }
        }
        Self { drives }
    }

    pub fn to_dos(&self, nt: &str) -> String {
        // Process-create notifications use the object-manager form `\??\C:\...`.
        if let Some(rest) = nt.strip_prefix("\\??\\") {
            return rest.to_string();
        }
        for (letter, dev) in &self.drives {
            if nt.len() > dev.len() && nt[..dev.len()].eq_ignore_ascii_case(dev) && nt.as_bytes()[dev.len()] == b'\\' {
                return format!("{letter}{}", &nt[dev.len()..]);
            }
        }
        nt.to_string()
    }

    pub fn to_nt(&self, dos: &str) -> String {
        for (letter, dev) in &self.drives {
            if dos.len() >= 2 && dos[..2].eq_ignore_ascii_case(letter) {
                return format!("{dev}{}", &dos[2..]);
            }
        }
        dos.to_string()
    }
}
