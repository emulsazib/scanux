//! ingest-writers: scanu.telemetry → ClickHouse `scanu.ocsf_events` + Neo4j graph.

use anyhow::Context;
use clap::Parser;
use ingest_bus::Bus;
use ingest_writers::GraphRows;
use prost::Message;
use scanu_proto::v1::EventEnvelope;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SCANU_KAFKA", default_value = "127.0.0.1:19092")]
    kafka: String,
    #[arg(long, env = "SCANU_CLICKHOUSE_URL", default_value = "http://127.0.0.1:8123")]
    clickhouse: String,
    #[arg(long, env = "SCANU_CLICKHOUSE_USER", default_value = "scanu")]
    ch_user: String,
    #[arg(long, env = "SCANU_CLICKHOUSE_PASSWORD", default_value = "scanu-dev")]
    ch_password: String,
    #[arg(long, env = "SCANU_NEO4J_URL", default_value = "http://127.0.0.1:7474")]
    neo4j: String,
    #[arg(long, env = "SCANU_NEO4J_USER", default_value = "neo4j")]
    neo4j_user: String,
    #[arg(long, env = "SCANU_NEO4J_PASSWORD", default_value = "scanu-dev-pass")]
    neo4j_password: String,
    #[arg(long, env = "SCANU_WRITERS_STATE", default_value = ".data/writers.offset")]
    state: PathBuf,
}

const CH_DDL: &[&str] = &[
    "CREATE DATABASE IF NOT EXISTS scanu",
    "CREATE TABLE IF NOT EXISTS scanu.ocsf_events (
        tenant_id LowCardinality(String),
        device_id String,
        event_id String,
        seq UInt64,
        class_uid UInt32,
        time DateTime64(3),
        ocsf String,
        ingested_at DateTime64(3) DEFAULT now64(3)
     ) ENGINE = MergeTree
     ORDER BY (tenant_id, device_id, time)
     TTL toDateTime(time) + INTERVAL 30 DAY",
];

const NEO_DDL: &[&str] = &[
    "CREATE CONSTRAINT proc_id IF NOT EXISTS FOR (n:Process) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT file_id IF NOT EXISTS FOR (n:File) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT dom_id IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT ep_id IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (n:Host) REQUIRE n.id IS UNIQUE",
    "CREATE INDEX proc_tenant IF NOT EXISTS FOR (n:Process) ON (n.tenant_id)",
];

struct Sinks {
    http: reqwest::Client,
    a: Args,
}

impl Sinks {
    async fn ch(&self, query: &str, body: String) -> anyhow::Result<()> {
        let r = self
            .http
            .post(&self.a.clickhouse)
            .query(&[("query", query)])
            .header("X-ClickHouse-User", &self.a.ch_user)
            .header("X-ClickHouse-Key", &self.a.ch_password)
            .body(body)
            .send()
            .await?;
        if !r.status().is_success() {
            anyhow::bail!("clickhouse: {}", r.text().await?);
        }
        Ok(())
    }

    /// Statements without data go in the body (ClickHouse requires a Content-Length on POST).
    async fn ch_body(&self, query: &str) -> anyhow::Result<()> {
        let r = self
            .http
            .post(&self.a.clickhouse)
            .header("X-ClickHouse-User", &self.a.ch_user)
            .header("X-ClickHouse-Key", &self.a.ch_password)
            .body(query.to_string())
            .send()
            .await?;
        if !r.status().is_success() {
            anyhow::bail!("clickhouse: {}", r.text().await?);
        }
        Ok(())
    }

    async fn neo(&self, statements: Vec<Value>) -> anyhow::Result<()> {
        let r = self
            .http
            .post(format!("{}/db/neo4j/tx/commit", self.a.neo4j))
            .basic_auth(&self.a.neo4j_user, Some(&self.a.neo4j_password))
            .json(&json!({ "statements": statements }))
            .send()
            .await?;
        let v: Value = r.json().await?;
        if let Some(errs) = v["errors"].as_array().filter(|e| !e.is_empty()) {
            anyhow::bail!("neo4j: {errs:?}");
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let a = Args::parse();
    let state = a.state.clone();
    let sinks = Sinks { http: reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?, a };
    for q in CH_DDL {
        sinks.ch_body(q).await.context("clickhouse DDL")?;
    }
    sinks.neo(NEO_DDL.iter().map(|s| json!({ "statement": s })).collect()).await.context("neo4j DDL")?;

    let bus = Bus::connect(&sinks.a.kafka, &["scanu.telemetry"]).await?;
    let start: i64 = std::fs::read_to_string(&state).ok().and_then(|s| s.trim().parse().ok()).map(|o: i64| o + 1).unwrap_or(-1);
    let mut rx = bus.subscribe_from("scanu.telemetry", start).await?;
    tracing::info!(start, "writers consuming scanu.telemetry");

    loop {
        // Gather up to 1000 messages or 500 ms.
        let Some(first) = rx.recv().await else { break };
        let mut msgs = vec![first];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while msgs.len() < 1000 {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(m)) => msgs.push(m),
                _ => break,
            }
        }
        let last_offset = msgs.last().map(|m| m.offset).unwrap_or(0);
        let mut ch_rows = String::new();
        let mut graphs: HashMap<(String, String), GraphRows> = HashMap::new();
        for m in &msgs {
            let h = |k: &str| String::from_utf8_lossy(m.headers.get(k).map(Vec::as_slice).unwrap_or_default()).to_string();
            let (tenant, device) = (h("tenant_id"), h("device_id"));
            let Ok(env) = EventEnvelope::decode(m.value.as_slice()) else { continue };
            let Ok(ocsf) = serde_json::from_slice::<Value>(&env.ocsf_json) else { continue };
            let time_ms = ocsf["time"].as_u64().unwrap_or(0);
            ch_rows.push_str(&json!({
                "tenant_id": tenant, "device_id": device, "event_id": env.event_id, "seq": env.seq,
                "class_uid": env.ocsf_class_uid,
                "time": chrono::DateTime::from_timestamp_millis(time_ms as i64).unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "ocsf": ocsf.to_string(),
            }).to_string());
            ch_rows.push('\n');
            graphs.entry((tenant.clone(), device.clone())).or_default().add(&tenant, &device, &ocsf);
        }
        if let Err(e) = sinks.ch("INSERT INTO scanu.ocsf_events SETTINGS date_time_input_format = 'best_effort' FORMAT JSONEachRow", ch_rows).await {
            tracing::error!(error = %e, "clickhouse insert failed; will retry batch");
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        for ((tenant, device), g) in graphs {
            if !g.is_empty() {
                if let Err(e) = sinks.neo(g.statements(&tenant, &device)).await {
                    tracing::error!(error = %e, "neo4j write failed");
                }
            }
        }
        std::fs::create_dir_all(state.parent().unwrap_or(std::path::Path::new("."))).ok();
        std::fs::write(&state, last_offset.to_string())?;
        tracing::info!(n = msgs.len(), last_offset, "batch written");
    }
    Ok(())
}

