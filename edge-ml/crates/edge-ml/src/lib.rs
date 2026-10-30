//! Multi-stage static analysis, run before an unknown executable starts and
//! fully offline:
//!
//! SHA-256 → known-bad bloom → PE/ELF features → classifier → YARA-X → [`Verdict`]

pub mod bloom;
pub mod features;
pub mod scorer;
#[cfg(feature = "yara")]
pub mod yara;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub use bloom::Bloom;
pub use features::{extract, Features, FEATURE_NAMES};
pub use scorer::{LinearScorer, Scorer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Malicious,
    Suspicious,
    Clean,
    NotExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub sha256: String,
    pub bloom_hit: bool,
    pub score: Option<f32>,
    pub model_version: String,
    pub yara: Vec<String>,
    pub top_features: Vec<String>,
    pub decision: Decision,
}

pub struct Thresholds {
    pub malicious: f32,
    pub suspicious: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { malicious: 0.98, suspicious: 0.80 }
    }
}

pub struct EdgeEngine {
    pub bloom: Option<Bloom>,
    pub scorer: Box<dyn Scorer>,
    #[cfg(feature = "yara")]
    pub yara: Option<yara::Rules>,
    pub thresholds: Thresholds,
    /// Larger files are hashed and bloom-checked but not parsed.
    pub max_parse_bytes: usize,
}

impl EdgeEngine {
    pub fn new(bloom: Option<Bloom>, scorer: Box<dyn Scorer>) -> Self {
        Self {
            bloom,
            scorer,
            #[cfg(feature = "yara")]
            yara: None,
            thresholds: Thresholds::default(),
            max_parse_bytes: 256 << 20,
        }
    }

    pub fn analyze_file(&self, path: &Path) -> std::io::Result<Verdict> {
        Ok(self.analyze_bytes(&std::fs::read(path)?))
    }

    pub fn analyze_bytes(&self, data: &[u8]) -> Verdict {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let sha256 = hex::encode(digest);
        let bloom_hit = self.bloom.as_ref().is_some_and(|b| b.contains(&digest));

        #[cfg(feature = "yara")]
        let yara = self.yara.as_ref().map(|r| r.scan(data)).unwrap_or_default();
        #[cfg(not(feature = "yara"))]
        let yara: Vec<String> = Vec::new();

        let feats = (data.len() <= self.max_parse_bytes).then(|| extract(data)).flatten();
        let (score, top_features) = match &feats {
            Some(f) => (Some(self.scorer.score(&f.values)), self.scorer.explain(&f.values, 3)),
            None => (None, vec![]),
        };
        let t = &self.thresholds;
        let decision = match (bloom_hit, score, feats.is_some()) {
            (true, _, _) => Decision::Malicious,
            (_, Some(s), _) if s >= t.malicious && !yara.is_empty() => Decision::Malicious,
            (_, Some(s), _) if s >= t.suspicious || !yara.is_empty() => Decision::Suspicious,
            (_, _, false) => Decision::NotExecutable,
            _ => Decision::Clean,
        };
        Verdict {
            sha256,
            bloom_hit,
            score,
            model_version: self.scorer.version().to_string(),
            yara,
            top_features,
            decision,
        }
    }
}

/// Synthetic PE builders for tests and the sensor simulator (no real malware in the repo).
pub mod testpe;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_hit_is_malicious_even_for_non_executables() {
        let data = b"just some bytes";
        let mut b = Bloom::with_capacity(100, 0.001);
        b.insert(&Sha256::digest(data).into());
        let e = EdgeEngine::new(Some(b), Box::new(LinearScorer::baseline()));
        let v = e.analyze_bytes(data);
        assert!(v.bloom_hit);
        assert_eq!(v.decision, Decision::Malicious);
    }

    #[test]
    fn plain_data_is_not_executable() {
        let e = EdgeEngine::new(None, Box::new(LinearScorer::baseline()));
        assert_eq!(e.analyze_bytes(b"hello").decision, Decision::NotExecutable);
    }

    #[test]
    fn benign_vs_injector_shaped_pe() {
        let e = EdgeEngine::new(None, Box::new(LinearScorer::baseline()));
        let benign = e.analyze_bytes(&testpe::tiny_pe64(testpe::Shape::Benign));
        let bad = e.analyze_bytes(&testpe::tiny_pe64(testpe::Shape::PackedRwx));
        assert!(benign.score.unwrap() < bad.score.unwrap(), "{benign:?} vs {bad:?}");
        assert_eq!(benign.decision, Decision::Clean);
        assert_ne!(bad.decision, Decision::Clean);
        assert!(!bad.top_features.is_empty());
    }
}
