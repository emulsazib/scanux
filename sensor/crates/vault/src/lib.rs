//! Encrypted quarantine vault with byte-identical restore.
//!
//! Layout under the vault root (protected from non-sensor writes by the
//! minifilter on Windows):
//!   blobs/<vault_id>.bin   AES-256-GCM(file_key, nonce, plaintext, aad=vault_id)
//!   index.jsonl            one hash-chained line per quarantine/restore
//!
//! Each file gets a random key, wrapped by the master key from a
//! [`KeyProvider`] (TPM/DPAPI on Windows, a file in dev). The original is
//! removed only after the ciphertext is fsynced and test-decrypted.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto failure (tampered or wrong key)")]
    Crypto,
    #[error("hash mismatch: expected {expected}, found {found}")]
    HashMismatch { expected: String, found: String },
    #[error("vault entry {0} not found")]
    NotFound(String),
    #[error("restore target already exists: {0}")]
    TargetExists(PathBuf),
    #[error("index corrupt at line {0}")]
    IndexCorrupt(usize),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Supplies the 256-bit master key. Implementations must never write it to disk in clear.
pub trait KeyProvider: Send + Sync {
    fn master_key(&self) -> Result<[u8; 32]>;
}

/// Dev/test provider. Production Windows uses the TPM-sealed provider in sensor-win.
pub struct StaticKey(pub [u8; 32]);

impl KeyProvider for StaticKey {
    fn master_key(&self) -> Result<[u8; 32]> {
        Ok(self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultEntry {
    pub vault_id: String,
    pub original_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at_ms: u64,
    /// Opaque platform metadata to restore (e.g. Windows SDDL, attributes).
    pub platform_meta: Option<String>,
    wrapped_key: String,
    key_nonce: String,
    data_nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexLine {
    op: String,
    entry: VaultEntry,
    at_ms: u64,
    prev_hash: String,
    hash: String,
}

pub struct Vault {
    root: PathBuf,
    keys: Box<dyn KeyProvider>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

impl Vault {
    pub fn open(root: impl Into<PathBuf>, keys: Box<dyn KeyProvider>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("blobs"))?;
        let v = Self { root, keys };
        v.verify_index()?;
        Ok(v)
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join("blobs").join(format!("{id}.bin"))
    }

    fn master(&self) -> Result<Aes256Gcm> {
        let k = self.keys.master_key()?;
        Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k)))
    }

    /// Encrypts `path` into the vault and removes the original.
    /// If `expected_sha256` is given, the file must still match it.
    pub fn quarantine(
        &self,
        path: &Path,
        expected_sha256: Option<&str>,
        platform_meta: Option<String>,
    ) -> Result<VaultEntry> {
        let data = fs::read(path)?;
        let sha = sha256_hex(&data);
        if let Some(exp) = expected_sha256 {
            if !exp.eq_ignore_ascii_case(&sha) {
                return Err(VaultError::HashMismatch { expected: exp.into(), found: sha });
            }
        }
        let vault_id = format!("vlt_{}", uuid::Uuid::now_v7().simple());

        let file_key: [u8; 32] = rand_bytes();
        let key_nonce: [u8; 12] = rand_bytes();
        let data_nonce: [u8; 12] = rand_bytes();
        let wrapped = self
            .master()?
            .encrypt(Nonce::from_slice(&key_nonce), Payload { msg: &file_key, aad: vault_id.as_bytes() })
            .map_err(|_| VaultError::Crypto)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&file_key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&data_nonce), Payload { msg: &data, aad: vault_id.as_bytes() })
            .map_err(|_| VaultError::Crypto)?;

        let blob = self.blob_path(&vault_id);
        {
            let mut f = File::create(&blob)?;
            f.write_all(&ct)?;
            f.sync_all()?;
        }
        let entry = VaultEntry {
            vault_id,
            original_path: path.to_path_buf(),
            sha256: sha,
            size: data.len() as u64,
            quarantined_at_ms: now_ms(),
            platform_meta,
            wrapped_key: hex::encode(wrapped),
            key_nonce: hex::encode(key_nonce),
            data_nonce: hex::encode(data_nonce),
        };
        // Prove we can get the bytes back before destroying the original.
        if self.decrypt(&entry)? != data {
            let _ = fs::remove_file(&blob);
            return Err(VaultError::Crypto);
        }
        self.append_index("quarantine", &entry)?;
        fs::remove_file(path)?;
        Ok(entry)
    }

    fn decrypt(&self, e: &VaultEntry) -> Result<Vec<u8>> {
        let hexd = |s: &str| hex::decode(s).map_err(|_| VaultError::Crypto);
        let file_key = self
            .master()?
            .decrypt(
                Nonce::from_slice(&hexd(&e.key_nonce)?),
                Payload { msg: &hexd(&e.wrapped_key)?, aad: e.vault_id.as_bytes() },
            )
            .map_err(|_| VaultError::Crypto)?;
        let ct = fs::read(self.blob_path(&e.vault_id))?;
        let pt = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&file_key))
            .decrypt(Nonce::from_slice(&hexd(&e.data_nonce)?), Payload { msg: &ct, aad: e.vault_id.as_bytes() })
            .map_err(|_| VaultError::Crypto)?;
        let found = sha256_hex(&pt);
        if found != e.sha256 {
            return Err(VaultError::HashMismatch { expected: e.sha256.clone(), found });
        }
        Ok(pt)
    }

    /// Restores a quarantined file to its original path, byte-identical.
    pub fn restore(&self, vault_id: &str) -> Result<VaultEntry> {
        let entry = self.get(vault_id)?.ok_or_else(|| VaultError::NotFound(vault_id.into()))?;
        if entry.original_path.exists() {
            return Err(VaultError::TargetExists(entry.original_path.clone()));
        }
        let pt = self.decrypt(&entry)?;
        if let Some(parent) = entry.original_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new().write(true).create_new(true).open(&entry.original_path)?;
        f.write_all(&pt)?;
        f.sync_all()?;
        self.append_index("restore", &entry)?;
        fs::remove_file(self.blob_path(vault_id))?;
        Ok(entry)
    }

    /// Entries currently held (quarantined and not restored).
    pub fn list(&self) -> Result<Vec<VaultEntry>> {
        let mut live: Vec<VaultEntry> = Vec::new();
        for line in self.read_index()? {
            match line.op.as_str() {
                "quarantine" => live.push(line.entry),
                "restore" => live.retain(|e| e.vault_id != line.entry.vault_id),
                _ => {}
            }
        }
        Ok(live)
    }

    pub fn get(&self, vault_id: &str) -> Result<Option<VaultEntry>> {
        Ok(self.list()?.into_iter().find(|e| e.vault_id == vault_id))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.jsonl")
    }

    fn read_index(&self) -> Result<Vec<IndexLine>> {
        let p = self.index_path();
        if !p.exists() {
            return Ok(vec![]);
        }
        BufReader::new(File::open(p)?)
            .lines()
            .map(|l| Ok(serde_json::from_str(&l?)?))
            .collect()
    }

    fn line_hash(prev: &str, op: &str, entry: &VaultEntry, at_ms: u64) -> Result<String> {
        let body = serde_json::to_vec(&(prev, op, entry, at_ms))?;
        Ok(sha256_hex(&body))
    }

    /// Detects edits/deletions of index lines (hash chain).
    pub fn verify_index(&self) -> Result<()> {
        let mut prev = String::from("genesis");
        for (i, l) in self.read_index()?.iter().enumerate() {
            if l.prev_hash != prev || Self::line_hash(&l.prev_hash, &l.op, &l.entry, l.at_ms)? != l.hash {
                return Err(VaultError::IndexCorrupt(i + 1));
            }
            prev = l.hash.clone();
        }
        Ok(())
    }

    fn append_index(&self, op: &str, entry: &VaultEntry) -> Result<()> {
        let prev = self.read_index()?.last().map(|l| l.hash.clone()).unwrap_or_else(|| "genesis".into());
        let at_ms = now_ms();
        let hash = Self::line_hash(&prev, op, entry, at_ms)?;
        let line = IndexLine { op: op.into(), entry: entry.clone(), at_ms, prev_hash: prev, hash };
        let mut f = OpenOptions::new().create(true).append(true).open(self.index_path())?;
        writeln!(f, "{}", serde_json::to_string(&line)?)?;
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Vault, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::open(d.path().join("vault"), Box::new(StaticKey([9; 32]))).unwrap();
        let f = d.path().join("docs").join("invoice.exe");
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, b"MZ\x90\x00 pretend malware").unwrap();
        (d, v, f)
    }

    #[test]
    fn quarantine_then_restore_is_byte_identical() {
        let (_d, v, f) = setup();
        let original = fs::read(&f).unwrap();
        let e = v.quarantine(&f, Some(&sha256_hex(&original)), None).unwrap();
        assert!(!f.exists());
        let blob = fs::read(v.blob_path(&e.vault_id)).unwrap();
        assert!(!blob.windows(5).any(|w| w == b"MZ\x90\x00 "), "blob must be encrypted");
        assert_eq!(v.list().unwrap().len(), 1);
        v.restore(&e.vault_id).unwrap();
        assert_eq!(fs::read(&f).unwrap(), original);
        assert!(v.list().unwrap().is_empty());
        v.verify_index().unwrap();
    }

    #[test]
    fn hash_mismatch_refuses_quarantine() {
        let (_d, v, f) = setup();
        let err = v.quarantine(&f, Some(&"00".repeat(32)), None).unwrap_err();
        assert!(matches!(err, VaultError::HashMismatch { .. }));
        assert!(f.exists(), "original untouched");
    }

    #[test]
    fn tampered_blob_fails_restore() {
        let (_d, v, f) = setup();
        let e = v.quarantine(&f, None, None).unwrap();
        let p = v.blob_path(&e.vault_id);
        let mut b = fs::read(&p).unwrap();
        b[0] ^= 0xff;
        fs::write(&p, b).unwrap();
        assert!(matches!(v.restore(&e.vault_id), Err(VaultError::Crypto)));
        assert!(!f.exists());
    }

    #[test]
    fn wrong_master_key_fails() {
        let (d, v, f) = setup();
        let e = v.quarantine(&f, None, None).unwrap();
        let v2 = Vault::open(d.path().join("vault"), Box::new(StaticKey([1; 32]))).unwrap();
        assert!(matches!(v2.restore(&e.vault_id), Err(VaultError::Crypto)));
    }

    #[test]
    fn edited_index_is_detected() {
        let (d, v, f) = setup();
        v.quarantine(&f, None, None).unwrap();
        let ip = d.path().join("vault/index.jsonl");
        let s = fs::read_to_string(&ip).unwrap().replace("invoice.exe", "benign.exe");
        fs::write(&ip, s).unwrap();
        assert!(matches!(
            Vault::open(d.path().join("vault"), Box::new(StaticKey([9; 32]))),
            Err(VaultError::IndexCorrupt(1))
        ));
    }

    #[test]
    fn restore_refuses_to_overwrite() {
        let (_d, v, f) = setup();
        let e = v.quarantine(&f, None, None).unwrap();
        fs::write(&f, b"new file").unwrap();
        assert!(matches!(v.restore(&e.vault_id), Err(VaultError::TargetExists(_))));
    }
}
