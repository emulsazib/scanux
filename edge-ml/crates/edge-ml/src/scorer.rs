use crate::features::{FEATURE_NAMES, NUM_FEATURES};
use serde::Deserialize;

pub trait Scorer: Send + Sync {
    /// Probability of maliciousness, 0..1.
    fn score(&self, x: &[f32; NUM_FEATURES]) -> f32;
    fn version(&self) -> &str;
    /// Names of the features pushing the score up the most (for explanations).
    fn explain(&self, _x: &[f32; NUM_FEATURES], _n: usize) -> Vec<String> {
        vec![]
    }
}

/// Logistic model over the static features. `baseline()` is a hand-weighted
/// heuristic that keeps the sensor protective before a trained model ships.
/// Trained logistic weights can be loaded with `from_json`.
pub struct LinearScorer {
    version: String,
    weights: [f32; NUM_FEATURES],
    bias: f32,
}

#[derive(Deserialize)]
struct LinearJson {
    version: String,
    bias: f32,
    weights: std::collections::HashMap<String, f32>,
}

impl LinearScorer {
    pub fn baseline() -> Self {
        let w = |name: &str| -> f32 {
            match name {
                "entropy" => 0.6,
                "is_64bit" => -0.2,
                "is_dll" => -0.2,
                "num_sections" => 0.05,
                "max_section_entropy" => 0.5,
                "num_wx_sections" => 1.5,
                "num_imports" => -0.01,
                "num_import_dlls" => -0.05,
                "suspicious_imports" => 0.6,
                "has_signature" => -2.5,
                "has_debug" => -0.7,
                "has_tls" => 0.6,
                "overlay_ratio" => 1.5,
                "packer_section" => 2.0,
                "entry_outside_code" => 1.5,
                "timestamp_anomaly" => 0.3,
                "num_exports" => -0.01,
                "url_count" => 0.2,
                _ => 0.0,
            }
        };
        let mut weights = [0f32; NUM_FEATURES];
        for (i, n) in FEATURE_NAMES.iter().enumerate() {
            weights[i] = w(n);
        }
        Self { version: "baseline-heuristic-1".into(), weights, bias: -8.0 }
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        let j: LinearJson = serde_json::from_str(s).map_err(|e| e.to_string())?;
        let mut weights = [0f32; NUM_FEATURES];
        for (k, w) in j.weights {
            let i = FEATURE_NAMES.iter().position(|n| *n == k).ok_or(format!("unknown feature {k}"))?;
            weights[i] = w;
        }
        Ok(Self { version: j.version, weights, bias: j.bias })
    }
}

impl Scorer for LinearScorer {
    fn score(&self, x: &[f32; NUM_FEATURES]) -> f32 {
        let z: f32 = self.bias + x.iter().zip(&self.weights).map(|(a, b)| a * b).sum::<f32>();
        1.0 / (1.0 + (-z).exp())
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn explain(&self, x: &[f32; NUM_FEATURES], n: usize) -> Vec<String> {
        let mut c: Vec<(f32, &str)> = x
            .iter()
            .zip(&self.weights)
            .zip(FEATURE_NAMES)
            .map(|((a, b), name)| (a * b, name))
            .filter(|(v, _)| *v > 0.5)
            .collect();
        c.sort_by(|a, b| b.0.total_cmp(&a.0));
        c.into_iter().take(n).map(|(_, n)| n.to_string()).collect()
    }
}

#[cfg(feature = "onnx")]
pub mod onnx {
    //! LightGBM exported via onnxmltools with `zipmap=False`:
    //! input "input" f32[N, 21], output "probabilities" f32[N, 2].

    use super::*;
    use std::sync::Mutex;

    pub struct OnnxScorer {
        session: Mutex<ort::session::Session>,
        version: String,
    }

    impl OnnxScorer {
        pub fn load(path: &std::path::Path, version: &str) -> ort::Result<Self> {
            let session = ort::session::Session::builder()?
                .with_intra_threads(1)?
                .commit_from_file(path)?;
            Ok(Self { session: Mutex::new(session), version: version.into() })
        }
    }

    impl Scorer for OnnxScorer {
        fn score(&self, x: &[f32; NUM_FEATURES]) -> f32 {
            let run = || -> ort::Result<f32> {
                let input = ort::value::Tensor::from_array(([1usize, NUM_FEATURES], x.to_vec()))?;
                let mut s = self.session.lock().expect("onnx session poisoned");
                let out = s.run(ort::inputs!["input" => input])?;
                let (_, probs) = out["probabilities"].try_extract_tensor::<f32>()?;
                Ok(probs[1])
            };
            // Fail safe: an inference error must not crash the sensor; the
            // caller still has bloom + YARA + canaries.
            run().unwrap_or(0.0)
        }

        fn version(&self) -> &str {
            &self.version
        }
    }
}
