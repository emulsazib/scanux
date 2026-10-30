//! On-device scrubbing applied before anything is spooled or uplinked.
//! Defaults minimize what leaves the device (see docs/ops.md §3).

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const CMDLINE_MAX: usize = 1024;
pub const SCRIPT_PREVIEW_MAX: usize = 2048;

pub struct Pseudonymizer {
    salt: [u8; 16],
}

fn profile_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?P<pre>[a-z]:\\users\\|/home/|/users/)(?P<name>[^\\/]+)").unwrap()
    })
}

fn secret_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        [
            r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)(\s*[=:]\s*|\s+)(\S+)",
            r"(?i)(authorization:\s*(bearer|basic)\s+)\S+",
            r"(?i)(https?://[^:/\s]+:)[^@\s]+@",
        ]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
    })
}

impl Pseudonymizer {
    pub fn new(salt: [u8; 16]) -> Self {
        Self { salt }
    }

    /// Stable per-device pseudonym, e.g. `u:7f3a9c01`.
    pub fn user(&self, name: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.salt);
        h.update(name.to_lowercase().as_bytes());
        format!("u:{}", &hex::encode(h.finalize())[..8])
    }

    /// Replaces the user-profile segment of a path with the user pseudonym.
    pub fn path(&self, path: &str) -> String {
        profile_re()
            .replace(path, |c: &regex::Captures| {
                format!("{}<{}>", &c["pre"], self.user(&c["name"]))
            })
            .into_owned()
    }
}

/// Removes obvious credentials from command lines / script text and truncates.
pub fn scrub_secrets(s: &str, max: usize) -> String {
    let res = secret_res();
    let mut out = res[0].replace_all(s, "$1$2***").into_owned();
    out = res[1].replace_all(&out, "${1}***").into_owned();
    out = res[2].replace_all(&out, "${1}***@").into_owned();
    truncate(&out, max)
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonymizes_windows_and_unix_profiles() {
        let p = Pseudonymizer::new([7; 16]);
        let w = p.path(r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Login Data");
        assert!(w.starts_with(r"C:\Users\<u:"), "{w}");
        assert!(!w.contains("Alice"));
        assert!(w.ends_with(r"\Login Data"));
        assert_eq!(p.user("alice"), p.user("ALICE"));
        assert!(!p.path("/home/bob/.ssh/id_rsa").contains("bob"));
        assert_eq!(p.path(r"C:\Windows\System32\cmd.exe"), r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn scrubs_credentials() {
        let s = scrub_secrets(
            "curl -H 'Authorization: Bearer abc.def' https://u:hunter2@x.io --password=hunter2 token hunter3",
            1024,
        );
        assert!(!s.contains("hunter2") && !s.contains("abc.def") && !s.contains("hunter3"), "{s}");
    }

    #[test]
    fn truncates_on_char_boundary() {
        let t = truncate("ééééé", 3);
        assert!(t.starts_with('é') && t.ends_with('…'));
    }
}
