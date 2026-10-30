//! Known-bad SHA-256 bloom filter. Inputs are already uniform hashes, so the
//! k probe positions come from double hashing over the digest bytes.
//!
//! File format: b"SCBLM001" | m_bits: u64 LE | k: u32 LE | bitset bytes

use std::io::{self, Read, Write};

const MAGIC: &[u8; 8] = b"SCBLM001";

#[derive(Clone)]
pub struct Bloom {
    m: u64,
    k: u32,
    bits: Vec<u8>,
}

impl Bloom {
    pub fn with_capacity(n: usize, fp_rate: f64) -> Self {
        let n = n.max(1) as f64;
        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * fp_rate.ln()) / (ln2 * ln2)).ceil().max(64.0) as u64;
        let k = ((m as f64 / n) * ln2).round().clamp(1.0, 30.0) as u32;
        Self { m, k, bits: vec![0; m.div_ceil(8) as usize] }
    }

    fn probes(&self, digest: &[u8; 32]) -> impl Iterator<Item = u64> + '_ {
        let h1 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(digest[8..16].try_into().unwrap()) | 1;
        (0..self.k as u64).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % self.m)
    }

    pub fn insert(&mut self, digest: &[u8; 32]) {
        let idx: Vec<u64> = self.probes(digest).collect();
        for i in idx {
            self.bits[(i / 8) as usize] |= 1 << (i % 8);
        }
    }

    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.probes(digest).all(|i| self.bits[(i / 8) as usize] & (1 << (i % 8)) != 0)
    }

    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(MAGIC)?;
        w.write_all(&self.m.to_le_bytes())?;
        w.write_all(&self.k.to_le_bytes())?;
        w.write_all(&self.bits)
    }

    pub fn read_from(r: &mut impl Read) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a scanu bloom file"));
        }
        let mut m = [0u8; 8];
        let mut k = [0u8; 4];
        r.read_exact(&mut m)?;
        r.read_exact(&mut k)?;
        let (m, k) = (u64::from_le_bytes(m), u32::from_le_bytes(k));
        if m == 0 || m > (1 << 36) || k == 0 || k > 30 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bloom header out of range"));
        }
        let mut bits = vec![0u8; m.div_ceil(8) as usize];
        r.read_exact(&mut bits)?;
        Ok(Self { m, k, bits })
    }

    /// Builds from newline-separated hex SHA-256 values (e.g. a MalwareBazaar export).
    pub fn from_hex_lines(text: &str, fp_rate: f64) -> Self {
        let hashes: Vec<[u8; 32]> = text
            .lines()
            .filter_map(|l| hex::decode(l.trim()).ok())
            .filter_map(|v| v.try_into().ok())
            .collect();
        let mut b = Self::with_capacity(hashes.len(), fp_rate);
        hashes.iter().for_each(|h| b.insert(h));
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn no_false_negatives_and_low_fp() {
        let mut b = Bloom::with_capacity(10_000, 0.001);
        let ins: Vec<[u8; 32]> = (0..10_000u32).map(|i| Sha256::digest(i.to_le_bytes()).into()).collect();
        ins.iter().for_each(|h| b.insert(h));
        assert!(ins.iter().all(|h| b.contains(h)));
        let fps = (10_000..60_000u32)
            .filter(|i| b.contains(&Sha256::digest(i.to_le_bytes()).into()))
            .count();
        assert!(fps < 150, "fp count {fps}");
    }

    #[test]
    fn round_trips_and_rejects_garbage() {
        let b = Bloom::from_hex_lines(&format!("{}\nnot-hex\n", "ab".repeat(32)), 0.01);
        let mut buf = vec![];
        b.write_to(&mut buf).unwrap();
        let b2 = Bloom::read_from(&mut buf.as_slice()).unwrap();
        assert!(b2.contains(&[0xab; 32]));
        assert!(Bloom::read_from(&mut &b"garbage!"[..]).is_err());
    }
}
