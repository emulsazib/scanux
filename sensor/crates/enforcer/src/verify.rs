//! Verification of cloud-issued commands. The sensor executes nothing that
//! fails any of these checks, and every rejection reason is reported back.

use crate::now_ms;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;
use scanu_proto::v1::{remediation_command::Tool, RemediationCommand, SignedCommand};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;

/// Longest validity window the sensor accepts, regardless of `not_after`.
pub const MAX_WINDOW_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("UNKNOWN_KEY")]
    UnknownKey,
    #[error("BAD_SIGNATURE")]
    BadSignature,
    #[error("MALFORMED")]
    Malformed,
    #[error("DEVICE_MISMATCH")]
    DeviceMismatch,
    #[error("EXPIRED")]
    Expired,
    #[error("WINDOW_TOO_LONG")]
    WindowTooLong,
    #[error("REPLAY")]
    Replay,
    #[error("APPROVAL_REQUIRED")]
    ApprovalRequired,
    #[error("NO_TOOL")]
    NoTool,
}

/// Persisted seen-set of (key_id, nonce) until the command would have expired anyway.
pub struct NonceStore {
    path: Option<PathBuf>,
    seen: HashSet<(String, u64)>,
    expiries: HashMap<(String, u64), u64>,
}

impl NonceStore {
    pub fn in_memory() -> Self {
        Self { path: None, seen: HashSet::new(), expiries: HashMap::new() }
    }

    pub fn load(path: PathBuf) -> std::io::Result<Self> {
        let mut s = Self { path: Some(path.clone()), seen: HashSet::new(), expiries: HashMap::new() };
        if let Ok(text) = std::fs::read_to_string(&path) {
            let now = now_ms();
            for line in text.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if let [k, n, exp] = parts[..] {
                    if let (Ok(n), Ok(exp)) = (n.parse::<u64>(), exp.parse::<u64>()) {
                        if exp + MAX_WINDOW_MS > now {
                            s.seen.insert((k.to_string(), n));
                            s.expiries.insert((k.to_string(), n), exp);
                        }
                    }
                }
            }
        }
        Ok(s)
    }

    fn check_and_insert(&mut self, key_id: &str, nonce: u64, not_after_ms: u64) -> bool {
        let k = (key_id.to_string(), nonce);
        if !self.seen.insert(k.clone()) {
            return false;
        }
        self.expiries.insert(k, not_after_ms);
        if let Some(p) = &self.path {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{key_id}\t{nonce}\t{not_after_ms}");
                let _ = f.sync_data();
            }
        }
        true
    }
}

pub struct CommandVerifier {
    pub device_id: String,
    /// Pinned signing keys (current + next for rotation), by key_id.
    pub keys: HashMap<String, VerifyingKey>,
    pub nonces: NonceStore,
}

/// Non-destructive tools: Tier-1 containment the sensor may also take on its
/// own, and read-only scans. Everything else needs a recorded human decision.
pub fn needs_approval(t: &Tool) -> bool {
    !matches!(t, Tool::Suspend(_) | Tool::NetBlock(_) | Tool::StartScan(_) | Tool::CancelScan(_))
}

fn ts_ms(ts: &prost_types::Timestamp) -> u64 {
    (ts.seconds.max(0) as u64) * 1000 + (ts.nanos.max(0) as u64) / 1_000_000
}

impl CommandVerifier {
    pub fn verify(&mut self, sc: &SignedCommand) -> Result<RemediationCommand, Reject> {
        self.verify_at(sc, now_ms())
    }

    pub fn verify_at(&mut self, sc: &SignedCommand, now: u64) -> Result<RemediationCommand, Reject> {
        let key = self.keys.get(&sc.key_id).ok_or(Reject::UnknownKey)?;
        let sig = Signature::from_slice(&sc.ed25519_sig).map_err(|_| Reject::BadSignature)?;
        key.verify(&sc.command, &sig).map_err(|_| Reject::BadSignature)?;
        let cmd = RemediationCommand::decode(sc.command.as_slice()).map_err(|_| Reject::Malformed)?;
        if cmd.device_id != self.device_id {
            return Err(Reject::DeviceMismatch);
        }
        let not_after = cmd.not_after.as_ref().map(ts_ms).ok_or(Reject::Malformed)?;
        if not_after <= now {
            return Err(Reject::Expired);
        }
        if not_after - now > MAX_WINDOW_MS {
            return Err(Reject::WindowTooLong);
        }
        let tool = cmd.tool.as_ref().ok_or(Reject::NoTool)?;
        if needs_approval(tool) && cmd.approval_ref.trim().is_empty() {
            return Err(Reject::ApprovalRequired);
        }
        // Only burn the nonce once everything else has passed.
        if !self.nonces.check_and_insert(&sc.key_id, cmd.nonce, not_after) {
            return Err(Reject::Replay);
        }
        Ok(cmd)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use scanu_proto::v1::{ProcessRef, QuarantineFile, SuspendProcess, TerminateProcess};

    pub fn signer() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    pub fn sign(sk: &SigningKey, key_id: &str, cmd: &RemediationCommand) -> SignedCommand {
        let bytes = cmd.encode_to_vec();
        SignedCommand { ed25519_sig: sk.sign(&bytes).to_bytes().to_vec(), command: bytes, key_id: key_id.into() }
    }

    pub fn cmd(now: u64, nonce: u64, tool: Tool, approval: &str) -> RemediationCommand {
        let na = now + 60_000;
        RemediationCommand {
            command_id: format!("cmd-{nonce}"),
            action_id: "act-1".into(),
            device_id: "dev-A".into(),
            not_after: Some(prost_types::Timestamp { seconds: (na / 1000) as i64, nanos: ((na % 1000) * 1_000_000) as i32 }),
            nonce,
            approval_ref: approval.into(),
            tool: Some(tool),
        }
    }

    fn verifier(sk: &SigningKey) -> CommandVerifier {
        CommandVerifier {
            device_id: "dev-A".into(),
            keys: HashMap::from([("k1".to_string(), sk.verifying_key())]),
            nonces: NonceStore::in_memory(),
        }
    }

    fn term() -> Tool {
        Tool::Terminate(TerminateProcess { process: Some(ProcessRef { pid: 5, start_time_unix_ms: 9, ..Default::default() }) })
    }

    #[test]
    fn accepts_valid_approved_command() {
        let sk = signer();
        let now = 1_700_000_000_000;
        let mut v = verifier(&sk);
        assert!(v.verify_at(&sign(&sk, "k1", &cmd(now, 1, term(), "dec-1")), now).is_ok());
    }

    #[test]
    fn rejects_forged_unknown_key_and_tampered() {
        let sk = signer();
        let now = 1_700_000_000_000;
        let mut v = verifier(&sk);
        // A5: attacker key, claiming our key_id.
        let forged = sign(&signer(), "k1", &cmd(now, 1, term(), "dec-1"));
        assert_eq!(v.verify_at(&forged, now), Err(Reject::BadSignature));
        let unknown = sign(&sk, "k-other", &cmd(now, 2, term(), "dec-1"));
        assert_eq!(v.verify_at(&unknown, now), Err(Reject::UnknownKey));
        let mut tampered = sign(&sk, "k1", &cmd(now, 3, term(), "dec-1"));
        let last = tampered.command.len() - 1;
        tampered.command[last] ^= 1;
        assert_eq!(v.verify_at(&tampered, now), Err(Reject::BadSignature));
    }

    #[test]
    fn rejects_replay_expiry_and_device_mismatch() {
        let sk = signer();
        let now = 1_700_000_000_000;
        let mut v = verifier(&sk);
        let sc = sign(&sk, "k1", &cmd(now, 7, term(), "dec-1"));
        v.verify_at(&sc, now).unwrap();
        assert_eq!(v.verify_at(&sc, now), Err(Reject::Replay)); // A4
        let sc = sign(&sk, "k1", &cmd(now, 8, term(), "dec-1"));
        assert_eq!(v.verify_at(&sc, now + 120_000), Err(Reject::Expired));
        let mut c = cmd(now, 9, term(), "dec-1");
        c.device_id = "dev-B".into();
        assert_eq!(v.verify_at(&sign(&sk, "k1", &c), now), Err(Reject::DeviceMismatch)); // A6
        let mut c = cmd(now, 10, term(), "dec-1");
        c.not_after = Some(prost_types::Timestamp { seconds: ((now + 86_400_000) / 1000) as i64, nanos: 0 });
        assert_eq!(v.verify_at(&sign(&sk, "k1", &c), now), Err(Reject::WindowTooLong));
    }

    #[test]
    fn non_tier1_tools_need_approval() {
        let sk = signer();
        let now = 1_700_000_000_000;
        let mut v = verifier(&sk);
        assert_eq!(v.verify_at(&sign(&sk, "k1", &cmd(now, 1, term(), "")), now), Err(Reject::ApprovalRequired)); // A7
        let q = Tool::Quarantine(QuarantineFile { path: "x".into(), sha256: "y".into() });
        assert_eq!(v.verify_at(&sign(&sk, "k1", &cmd(now, 2, q, " ")), now), Err(Reject::ApprovalRequired));
        let s = Tool::Suspend(SuspendProcess { process: None });
        assert!(v.verify_at(&sign(&sk, "k1", &cmd(now, 3, s, "")), now).is_ok());
        let scan = Tool::StartScan(scanu_proto::v1::StartScan { scan_id: "scn_1".into(), scope: 2 });
        assert!(v.verify_at(&sign(&sk, "k1", &cmd(now, 4, scan, "")), now).is_ok(), "scans are read-only");
    }

    #[test]
    fn nonce_store_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nonces.tsv");
        let sk = signer();
        let now = now_ms();
        let sc = sign(&sk, "k1", &cmd(now, 42, term(), "dec-1"));
        let mut v = verifier(&sk);
        v.nonces = NonceStore::load(p.clone()).unwrap();
        v.verify_at(&sc, now).unwrap();
        let mut v2 = verifier(&sk);
        v2.nonces = NonceStore::load(p).unwrap();
        assert_eq!(v2.verify_at(&sc, now), Err(Reject::Replay));
    }
}
