//! Lightweight streaming detectors that run on every event without TLS
//! interception: DNS DGA/tunneling, beaconing, and mass file modification.

use crate::event::ProcessKey;
use std::collections::{HashMap, VecDeque};

fn shannon(s: &str) -> f32 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// 0..1 likelihood that the registrable label of `name` was algorithmically
/// generated. Heuristic baseline; replaced by a char-n-gram model in edge-ml later.
pub fn dga_score(name: &str) -> f32 {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return 0.0;
    }
    let label = labels[labels.len() - 2].to_ascii_lowercase();
    if label.len() < 6 {
        return 0.0;
    }
    let len = label.len() as f32;
    let digits = label.bytes().filter(u8::is_ascii_digit).count() as f32 / len;
    let vowels = label.bytes().filter(|b| b"aeiou".contains(b)).count() as f32 / len;
    let mut max_consonant_run = 0;
    let mut run = 0;
    for b in label.bytes() {
        if b.is_ascii_alphabetic() && !b"aeiou".contains(&b) {
            run += 1;
            max_consonant_run = max_consonant_run.max(run);
        } else {
            run = 0;
        }
    }
    let x = 1.6 * shannon(&label) + 3.0 * digits - 4.0 * vowels
        + 0.35 * max_consonant_run as f32
        + 0.08 * len
        - 6.2;
    sigmoid(x)
}

/// 0..1 likelihood of DNS tunneling: long, high-entropy subdomains.
pub fn dns_tunnel_score(name: &str) -> f32 {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() < 3 {
        return 0.0;
    }
    let sub = labels[..labels.len() - 2].join("");
    let longest = labels.iter().map(|l| l.len()).max().unwrap_or(0) as f32;
    let x = 0.06 * sub.len() as f32 + 0.05 * longest + 1.2 * shannon(&sub) - 8.0;
    sigmoid(x)
}

/// Flags (process, remote) pairs that connect at near-constant intervals.
pub struct BeaconTracker {
    history: HashMap<(ProcessKey, String), VecDeque<u64>>,
    min_intervals: usize,
    max_cv: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Beacon {
    pub mean_interval_ms: f32,
    pub jitter_cv: f32,
}

impl Default for BeaconTracker {
    fn default() -> Self {
        Self { history: HashMap::new(), min_intervals: 8, max_cv: 0.15 }
    }
}

impl BeaconTracker {
    pub fn observe(&mut self, p: ProcessKey, remote: &str, t_ms: u64) -> Option<Beacon> {
        let h = self.history.entry((p, remote.to_string())).or_default();
        h.push_back(t_ms);
        if h.len() > 17 {
            h.pop_front();
        }
        if h.len() <= self.min_intervals {
            return None;
        }
        let iv: Vec<f32> = h.iter().zip(h.iter().skip(1)).map(|(a, b)| (b - a) as f32).collect();
        let mean = iv.iter().sum::<f32>() / iv.len() as f32;
        if mean < 1000.0 {
            return None;
        }
        let var = iv.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / iv.len() as f32;
        let cv = var.sqrt() / mean;
        (cv <= self.max_cv).then_some(Beacon { mean_interval_ms: mean, jitter_cv: cv })
    }

    pub fn forget(&mut self, p: ProcessKey) {
        self.history.retain(|(k, _), _| *k != p);
    }
}

/// Counts distinct files written/renamed per process in a sliding window.
/// Complements canaries for encryptors that skip hidden files.
pub struct MassModifyTracker {
    window_ms: u64,
    threshold: usize,
    events: HashMap<ProcessKey, VecDeque<(u64, u64)>>,
}

impl MassModifyTracker {
    pub fn new(window_ms: u64, threshold: usize) -> Self {
        Self { window_ms, threshold, events: HashMap::new() }
    }

    /// Returns the count in the window when it crosses the threshold.
    pub fn observe(&mut self, p: ProcessKey, path: &str, t_ms: u64) -> Option<usize> {
        let path_hash = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            path.to_lowercase().hash(&mut h);
            h.finish()
        };
        let q = self.events.entry(p).or_default();
        while q.front().is_some_and(|(t, _)| t + self.window_ms < t_ms) {
            q.pop_front();
        }
        if !q.iter().any(|(_, h)| *h == path_hash) {
            q.push_back((t_ms, path_hash));
        }
        (q.len() >= self.threshold).then_some(q.len())
    }

    pub fn forget(&mut self, p: ProcessKey) {
        self.events.remove(&p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dga_separates_random_from_words() {
        for benign in ["google.com", "microsoft.com", "wikipedia.org", "githubusercontent.com"] {
            assert!(dga_score(benign) < 0.5, "{benign}: {}", dga_score(benign));
        }
        for dga in ["xjw3kq9zr7vtp2.com", "qzxkvbrtplmw.net", "a8f3k2l9x7q1z0.info"] {
            assert!(dga_score(dga) > 0.5, "{dga}: {}", dga_score(dga));
        }
    }

    #[test]
    fn tunnel_scores_long_encoded_subdomains() {
        assert!(dns_tunnel_score("www.example.com") < 0.2);
        let t = "mzxw6ytboi2dgnbvgy3tqojqgezdgnbvgy3tqojq.mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dz.t.evil.net";
        assert!(dns_tunnel_score(t) > 0.8, "{}", dns_tunnel_score(t));
    }

    #[test]
    fn beacon_detects_regular_intervals_only() {
        let p = ProcessKey { pid: 1, start_time_ms: 0 };
        let mut bt = BeaconTracker::default();
        let mut hit = None;
        for i in 0..10u64 {
            hit = bt.observe(p, "203.0.113.5:443", i * 60_000 + (i % 3) * 500);
        }
        assert!(hit.is_some());
        let mut bt = BeaconTracker::default();
        let jittery = [0u64, 5_000, 70_000, 71_000, 200_000, 260_000, 261_000, 400_000, 900_000, 905_000];
        assert!(jittery.iter().all(|t| bt.observe(p, "x", *t).is_none()));
    }

    #[test]
    fn mass_modify_threshold() {
        let p = ProcessKey { pid: 2, start_time_ms: 0 };
        let mut m = MassModifyTracker::new(5_000, 20);
        let hits: Vec<_> = (0..25).filter_map(|i| m.observe(p, &format!("f{i}.doc"), i * 10)).collect();
        assert!(!hits.is_empty());
        // Same file repeatedly never trips.
        let mut m = MassModifyTracker::new(5_000, 20);
        assert!((0..100).all(|i| m.observe(p, "same.doc", i).is_none()));
    }
}
