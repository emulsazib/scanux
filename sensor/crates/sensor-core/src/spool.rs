//! Local durable spool (redb, pure Rust; no C on the endpoint). Keeps telemetry
//! while the cloud is unreachable; evicts lowest priority, oldest first, once
//! over the size cap.
//!
//! Tables:
//!   spool: seq → [priority u8] ++ envelope bytes
//!   evict: (priority << 64 | seq) → size, ordered for eviction

use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

const DATA: TableDefinition<u64, &[u8]> = TableDefinition::new("spool");
const EVICT: TableDefinition<u128, u64> = TableDefinition::new("evict");

/// Boxed: redb's error type is large and would bloat every `Result`.
#[derive(Debug, thiserror::Error)]
#[error("spool: {0}")]
pub struct SpoolError(Box<redb::Error>);

macro_rules! from_redb {
    ($($t:ty),*) => {$(impl From<$t> for SpoolError { fn from(e: $t) -> Self { Self(Box::new(e.into())) } })*};
}
from_redb!(redb::Error, redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub struct Spool {
    db: Database,
    cap_bytes: u64,
    total_bytes: u64,
    dropped: u64,
}

fn evict_key(priority: u8, seq: u64) -> u128 {
    ((priority as u128) << 64) | seq as u128
}

impl Spool {
    pub fn open(path: &Path, cap_bytes: u64) -> Result<Self, SpoolError> {
        Self::init(Database::create(path)?, cap_bytes)
    }

    pub fn in_memory(cap_bytes: u64) -> Result<Self, SpoolError> {
        Self::init(Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?, cap_bytes)
    }

    fn init(db: Database, cap_bytes: u64) -> Result<Self, SpoolError> {
        let w = db.begin_write()?;
        let mut total = 0;
        {
            w.open_table(DATA)?;
            let ev = w.open_table(EVICT)?;
            for item in ev.iter()? {
                total += item?.1.value();
            }
        }
        w.commit()?;
        Ok(Self { db, cap_bytes, total_bytes: total, dropped: 0 })
    }

    pub fn append(&mut self, seq: u64, priority: i32, bytes: &[u8]) -> Result<(), SpoolError> {
        let prio = priority.clamp(0, 255) as u8;
        let w = self.db.begin_write()?;
        {
            let mut data = w.open_table(DATA)?;
            let mut ev = w.open_table(EVICT)?;
            let mut v = Vec::with_capacity(bytes.len() + 1);
            v.push(prio);
            v.extend_from_slice(bytes);
            data.insert(seq, v.as_slice())?;
            ev.insert(evict_key(prio, seq), bytes.len() as u64)?;
            self.total_bytes += bytes.len() as u64;
            while self.total_bytes > self.cap_bytes {
                let Some((k, size)) = ev.first()?.map(|(k, v)| (k.value(), v.value())) else { break };
                ev.remove(k)?;
                data.remove(k as u64)?;
                self.total_bytes -= size;
                self.dropped += 1;
            }
        }
        w.commit()?;
        Ok(())
    }

    /// Oldest-first batch of entries with seq > `after`.
    pub fn batch_after(&self, after: u64, limit: usize) -> Result<Vec<(u64, Vec<u8>)>, SpoolError> {
        let r = self.db.begin_read()?;
        let data = r.open_table(DATA)?;
        let mut out = Vec::new();
        for item in data.range(after.saturating_add(1)..)?.take(limit) {
            let (k, v) = item?;
            out.push((k.value(), v.value()[1..].to_vec()));
        }
        Ok(out)
    }

    /// Cloud durably accepted everything up to `seq`.
    pub fn ack(&mut self, seq: u64) -> Result<(), SpoolError> {
        let w = self.db.begin_write()?;
        {
            let mut data = w.open_table(DATA)?;
            let mut ev = w.open_table(EVICT)?;
            let doomed: Vec<(u64, u8, u64)> = data
                .range(..=seq)?
                .map(|i| i.map(|(k, v)| (k.value(), v.value()[0], (v.value().len() - 1) as u64)))
                .collect::<Result<_, _>>()?;
            for (s, prio, size) in doomed {
                data.remove(s)?;
                ev.remove(evict_key(prio, s))?;
                self.total_bytes -= size;
            }
        }
        w.commit()?;
        Ok(())
    }

    pub fn last_seq(&self) -> Result<u64, SpoolError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(DATA)?.last()?.map(|(k, _)| k.value()).unwrap_or(0))
    }

    pub fn len(&self) -> Result<u64, SpoolError> {
        let r = self.db.begin_read()?;
        Ok(redb::ReadableTableMetadata::len(&r.open_table(DATA)?)?)
    }

    pub fn is_empty(&self) -> Result<bool, SpoolError> {
        Ok(self.len()? == 0)
    }

    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_batch_ack() {
        let mut s = Spool::in_memory(1 << 20).unwrap();
        for i in 1..=5 {
            s.append(i, 1, &[i as u8; 10]).unwrap();
        }
        let b = s.batch_after(2, 10).unwrap();
        assert_eq!(b.iter().map(|x| x.0).collect::<Vec<_>>(), vec![3, 4, 5]);
        assert_eq!(b[0].1, vec![3u8; 10]);
        s.ack(4).unwrap();
        assert_eq!(s.len().unwrap(), 1);
        assert_eq!(s.last_seq().unwrap(), 5);
    }

    #[test]
    fn evicts_low_priority_first() {
        let mut s = Spool::in_memory(100).unwrap();
        s.append(1, 3, &[0; 40]).unwrap(); // critical
        s.append(2, 1, &[0; 40]).unwrap(); // bulk
        s.append(3, 2, &[0; 40]).unwrap(); // over cap → evict seq 2
        let seqs: Vec<u64> = s.batch_after(0, 10).unwrap().into_iter().map(|x| x.0).collect();
        assert_eq!(seqs, vec![1, 3]);
        assert_eq!(s.take_dropped(), 1);
    }

    #[test]
    fn survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("spool.redb");
        {
            let mut s = Spool::open(&p, 1 << 20).unwrap();
            s.append(7, 2, b"hello").unwrap();
        }
        let s = Spool::open(&p, 1 << 20).unwrap();
        assert_eq!(s.last_seq().unwrap(), 7);
        assert_eq!(s.batch_after(0, 10).unwrap()[0].1, b"hello");
    }
}
