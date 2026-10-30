//! Ransomware canaries: hidden decoy files placed where bulk encryptors look
//! first. Any write/rename/delete on one is treated as high-confidence
//! destructive behaviour (Tier-1). The Windows minifilter gets the same list
//! and denies the I/O in kernel before notifying the service.

use rand::RngCore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanarySpec {
    pub id: String,
    pub path: PathBuf,
    pub content: Vec<u8>,
}

#[derive(Default)]
pub struct CanarySet {
    by_path: HashMap<String, String>,
}

/// Case-insensitive, separator-normalized key (Windows paths are case-insensitive).
pub fn path_key(p: &str) -> String {
    p.replace('/', "\\").to_lowercase()
}

/// Two decoys per directory: one sorting first and one sorting last, since
/// encryptors usually walk directories alphabetically in either direction.
pub fn plan(dirs: &[PathBuf]) -> Vec<CanarySpec> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::new();
    for dir in dirs {
        for (prefix, ext, magic) in [
            ("!000_", "docx", &b"PK\x03\x04"[..]),
            ("~zzz_", "xlsx", &b"PK\x03\x04"[..]),
        ] {
            let mut tag = [0u8; 4];
            rng.fill_bytes(&mut tag);
            let id = format!("cn_{}", hex::encode(tag));
            let mut content = magic.to_vec();
            let mut body = vec![0u8; 4096];
            rng.fill_bytes(&mut body);
            content.extend_from_slice(&body);
            out.push(CanarySpec {
                path: dir.join(format!("{prefix}archive_{}.{ext}", hex::encode(tag))),
                id,
                content,
            });
        }
    }
    out
}

/// Writes canary files. Platform code applies hidden/system attributes.
pub fn deploy(specs: &[CanarySpec]) -> std::io::Result<()> {
    for s in specs {
        if let Some(parent) = s.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&s.path, &s.content)?;
    }
    Ok(())
}

impl CanarySet {
    pub fn new(specs: &[CanarySpec]) -> Self {
        Self {
            by_path: specs
                .iter()
                .map(|s| (path_key(&s.path.to_string_lossy()), s.id.clone()))
                .collect(),
        }
    }

    pub fn match_path(&self, path: &str) -> Option<&str> {
        self.by_path.get(&path_key(path)).map(String::as_str)
    }

    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.by_path.keys()
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

pub fn exists_all(specs: &[CanarySpec]) -> bool {
    specs.iter().all(|s| Path::new(&s.path).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_deploy_and_match_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let specs = plan(&[dir.path().to_path_buf()]);
        assert_eq!(specs.len(), 2);
        deploy(&specs).unwrap();
        assert!(exists_all(&specs));
        let set = CanarySet::new(&specs);
        let p = specs[0].path.to_string_lossy().to_uppercase();
        assert_eq!(set.match_path(&p), Some(specs[0].id.as_str()));
        assert!(set.match_path("/tmp/not-a-canary.docx").is_none());
    }
}
