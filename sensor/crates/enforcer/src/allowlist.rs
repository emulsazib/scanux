use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

/// User-approved hashes ("Allow & Whitelist"). Persisted as one hash per line.
pub struct Allowlist {
    path: Option<PathBuf>,
    set: HashSet<String>,
}

impl Allowlist {
    pub fn in_memory() -> Self {
        Self { path: None, set: HashSet::new() }
    }

    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let set = match std::fs::read_to_string(&path) {
            Ok(s) => s.lines().map(|l| l.trim().to_lowercase()).filter(|l| l.len() == 64).collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => return Err(e),
        };
        Ok(Self { path: Some(path), set })
    }

    pub fn contains(&self, sha256: &str) -> bool {
        self.set.contains(&sha256.to_lowercase())
    }

    pub fn insert(&mut self, sha256: &str) -> std::io::Result<()> {
        let h = sha256.to_lowercase();
        if self.set.insert(h.clone()) {
            if let Some(p) = &self.path {
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p)?;
                writeln!(f, "{h}")?;
            }
        }
        Ok(())
    }
}
