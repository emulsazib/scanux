//! Long-lived mTLS gRPC link to the ingest gateway. Protection never depends
//! on it: while disconnected, events accumulate in the spool and Tier-1 keeps
//! working; this task just reconnects with backoff.

use crate::engine::Engine;
use scanu_proto::v1::{
    sensor_link_service_client::SensorLinkServiceClient, stream_request, stream_response, Heartbeat, Hello,
    StreamRequest,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

#[derive(Clone)]
pub struct UplinkConfig {
    pub endpoint: String,
    /// TLS server name expected in the gateway certificate.
    pub domain: String,
    /// The pinned CA. OS trust stores are never consulted.
    pub ca_pem: Vec<u8>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub os: String,
    pub batch_size: usize,
    pub flush_every: Duration,
}

async fn connect(cfg: &UplinkConfig) -> Result<SensorLinkServiceClient<Channel>, tonic::transport::Error> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&cfg.ca_pem))
        .identity(Identity::from_pem(&cfg.cert_pem, &cfg.key_pem))
        .domain_name(cfg.domain.clone());
    let ch = Channel::from_shared(cfg.endpoint.clone())
        .expect("valid endpoint uri")
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .connect()
        .await?;
    Ok(SensorLinkServiceClient::new(ch))
}

/// Runs forever (until `shutdown` fires), reconnecting as needed.
pub async fn run(engine: Arc<Mutex<Engine>>, cfg: UplinkConfig, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *shutdown.borrow() {
            return;
        }
        match session(&engine, &cfg, &mut shutdown).await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?backoff, "uplink down (local protection continues)");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown.changed() => return,
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

async fn session(
    engine: &Arc<Mutex<Engine>>,
    cfg: &UplinkConfig,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = connect(cfg).await?;
    let (tx, rx) = mpsc::channel::<StreamRequest>(64);
    let (last_seq, model) = {
        let e = engine.lock().unwrap();
        (e.last_seq(), e.edge_model_version())
    };
    tx.send(StreamRequest {
        msg: Some(stream_request::Msg::Hello(Hello {
            sensor_version: env!("CARGO_PKG_VERSION").into(),
            os: cfg.os.clone(),
            os_version: String::new(),
            last_seq,
            edge_model_version: model,
        })),
    })
    .await?;
    let mut inbound = client.stream(ReceiverStream::new(rx)).await?.into_inner();
    tracing::info!(endpoint = %cfg.endpoint, "uplink connected");

    let mut sent_upto = 0u64;
    let mut flush = tokio::time::interval(cfg.flush_every);
    let mut hb = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                // Final flush so short-lived runs (simulator) deliver everything.
                drain(engine, &tx, &mut sent_upto, cfg.batch_size).await?;
                return Ok(());
            }
            _ = flush.tick() => drain(engine, &tx, &mut sent_upto, cfg.batch_size).await?,
            _ = hb.tick() => {
                let seq = engine.lock().unwrap().last_seq();
                tx.send(StreamRequest { msg: Some(stream_request::Msg::Heartbeat(Heartbeat {
                    seq, cpu_percent: 0.0, rss_bytes: 0, driver_connected: false,
                }))}).await?;
            }
            msg = inbound.message() => {
                let Some(msg) = msg? else { return Err("gateway closed stream".into()) };
                match msg.msg {
                    Some(stream_response::Msg::AckSeq(s)) => engine.lock().unwrap().ack(s)?,
                    Some(stream_response::Msg::Command(sc)) => {
                        let res = engine.lock().unwrap().handle_command(&sc);
                        crate::scan::spawn_pending(engine);
                        tracing::info!(command_id = %res.command_id, status = res.status, reason = %res.reason, "command handled");
                        drain(engine, &tx, &mut sent_upto, cfg.batch_size).await?;
                    }
                    Some(stream_response::Msg::Prompt(p)) => {
                        tracing::info!(action_id = %p.action_id, title = %p.title, "HITL prompt received (forwarded to desktop)");
                    }
                    None => {}
                }
            }
        }
    }
}

async fn drain(
    engine: &Arc<Mutex<Engine>>,
    tx: &mpsc::Sender<StreamRequest>,
    sent_upto: &mut u64,
    batch_size: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (batch, last, alerts, results, scans) = {
            let mut e = engine.lock().unwrap();
            let (batch, last) = e.batch_after(*sent_upto, batch_size)?;
            let alerts: Vec<_> = e.outbox_alerts.drain(..).collect();
            let results: Vec<_> = e.outbox_results.drain(..).collect();
            let scans: Vec<_> = e.outbox_scans.drain(..).collect();
            (batch, last, alerts, results, scans)
        };
        let empty = batch.events.is_empty();
        if !empty {
            tx.send(StreamRequest { msg: Some(stream_request::Msg::Batch(batch)) }).await?;
            *sent_upto = last;
        }
        for a in alerts {
            tx.send(StreamRequest { msg: Some(stream_request::Msg::Alert(a)) }).await?;
        }
        for r in results {
            tx.send(StreamRequest { msg: Some(stream_request::Msg::CommandResult(r)) }).await?;
        }
        for p in scans {
            tx.send(StreamRequest { msg: Some(stream_request::Msg::ScanProgress(p)) }).await?;
        }
        if empty {
            return Ok(());
        }
    }
}
