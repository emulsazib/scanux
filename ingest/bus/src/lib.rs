//! Kafka access via rskafka (pure Rust, no librdkafka). Dev topics use one
//! partition; production keys by device_id over N partitions.

use rskafka::client::partition::{Compression, OffsetAt, PartitionClient, UnknownTopicHandling};
use rskafka::client::{Client, ClientBuilder};
use rskafka::record::Record;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

pub struct Bus {
    client: Client,
    parts: Mutex<HashMap<String, Arc<PartitionClient>>>,
}

pub struct Message {
    pub offset: i64,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub headers: BTreeMap<String, Vec<u8>>,
}

impl Bus {
    /// Connects (retrying while the broker starts) and ensures topics exist.
    pub async fn connect(brokers: &str, topics: &[&str]) -> anyhow::Result<Self> {
        let mut attempt = 0;
        let client = loop {
            match ClientBuilder::new(brokers.split(',').map(str::to_string).collect()).build().await {
                Ok(c) => break c,
                Err(e) if attempt < 30 => {
                    attempt += 1;
                    tracing::warn!(error = %e, "kafka not reachable yet, retrying");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        let ctl = client.controller_client()?;
        let existing: Vec<String> = client.list_topics().await?.into_iter().map(|t| t.name).collect();
        for t in topics {
            if !existing.iter().any(|e| e == t) {
                if let Err(e) = ctl.create_topic(*t, 1, 1, 5_000).await {
                    tracing::debug!(topic = t, error = %e, "create_topic (may already exist)");
                }
            }
        }
        Ok(Self { client, parts: Mutex::new(HashMap::new()) })
    }

    async fn part(&self, topic: &str) -> anyhow::Result<Arc<PartitionClient>> {
        let mut p = self.parts.lock().await;
        if let Some(c) = p.get(topic) {
            return Ok(c.clone());
        }
        let c = Arc::new(self.client.partition_client(topic, 0, UnknownTopicHandling::Retry).await?);
        p.insert(topic.to_string(), c.clone());
        Ok(c)
    }

    pub async fn publish(
        &self,
        topic: &str,
        records: Vec<(Vec<u8>, Vec<u8>)>,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let h: BTreeMap<String, Vec<u8>> =
            headers.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect();
        let now = chrono::Utc::now();
        let recs = records
            .into_iter()
            .map(|(k, v)| Record { key: Some(k), value: Some(v), headers: h.clone(), timestamp: now })
            .collect();
        self.part(topic).await?.produce(recs, Compression::NoCompression).await?;
        Ok(())
    }

    /// Streams values produced after this call.
    pub async fn subscribe_latest(&self, topic: &str) -> anyhow::Result<mpsc::Receiver<Vec<u8>>> {
        let p = self.part(topic).await?;
        let start = p.get_offset(OffsetAt::Latest).await?;
        let mut rx = self.subscribe_from(topic, start).await?;
        let (tx, out) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if tx.send(m.value).await.is_err() {
                    break;
                }
            }
        });
        Ok(out)
    }

    /// Streams messages starting at `offset` (use -1 for earliest).
    pub async fn subscribe_from(&self, topic: &str, offset: i64) -> anyhow::Result<mpsc::Receiver<Message>> {
        let p = self.part(topic).await?;
        let mut next = if offset < 0 { p.get_offset(OffsetAt::Earliest).await? } else { offset };
        let (tx, rx) = mpsc::channel(1024);
        let topic = topic.to_string();
        tokio::spawn(async move {
            loop {
                match p.fetch_records(next, 1..4_000_000, 500).await {
                    Ok((recs, _hw)) => {
                        for r in recs {
                            next = r.offset + 1;
                            let m = Message {
                                offset: r.offset,
                                key: r.record.key.unwrap_or_default(),
                                value: r.record.value.unwrap_or_default(),
                                headers: r.record.headers,
                            };
                            if tx.send(m).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%topic, error = %e, "fetch failed; retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(rx)
    }
}
