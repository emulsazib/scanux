#![allow(clippy::result_large_err)] // tonic::Status is large by design
//! ingest-gateway: terminates sensor mTLS, derives (tenant, device) from the
//! client certificate's SPIFFE URI SAN, and bridges sensors <-> Kafka.
//!
//! Kafka topics (single partition in dev):
//!   scanu.telemetry    EventEnvelope protobuf, key=device_id, headers tenant_id/device_id
//!   scanu.alerts       Alert as JSON (consumed by agents)
//!   scanu.cmd-results  CommandResult as JSON (consumed by api)
//!   scanu.commands     {tenant_id, device_id, signed_command_b64} from api → routed to the device stream
//!   scanu.scan-progress ScanProgress as JSON (consumed by api)
//!   scanu.device-events {online|offline} presence (consumed by api)

mod convert;
mod identity;

use anyhow::Context;
use base64::Engine as _;
use ingest_bus::Bus;
use clap::Parser;
use prost::Message;
use scanu_proto::v1::{
    sensor_link_service_server::{SensorLinkService, SensorLinkServiceServer},
    stream_request, stream_response, EnrollRequest, EnrollResponse, RemediationCommand, SignedCommand,
    StreamRequest, StreamResponse,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

pub const T_TELEMETRY: &str = "scanu.telemetry";
pub const T_ALERTS: &str = "scanu.alerts";
pub const T_RESULTS: &str = "scanu.cmd-results";
pub const T_COMMANDS: &str = "scanu.commands";
pub const T_SCANS: &str = "scanu.scan-progress";
pub const T_DEVICES: &str = "scanu.device-events";

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SCANU_GATEWAY_LISTEN", default_value = "127.0.0.1:7443")]
    listen: String,
    #[arg(long, env = "SCANU_KAFKA", default_value = "127.0.0.1:19092")]
    kafka: String,
    #[arg(long, env = "SCANU_PKI", default_value = "deploy/pki/out")]
    pki: std::path::PathBuf,
}

type Tx = mpsc::Sender<Result<StreamResponse, Status>>;

#[derive(Default)]
struct Registry {
    streams: HashMap<(String, String), Tx>,
    /// Commands for devices that are not connected right now (bounded, expiry-checked on delivery).
    pending: HashMap<(String, String), Vec<SignedCommand>>,
    last_seq: HashMap<(String, String), u64>,
}

struct Gateway {
    bus: Arc<Bus>,
    reg: Arc<Mutex<Registry>>,
}

fn not_expired(sc: &SignedCommand) -> bool {
    RemediationCommand::decode(sc.command.as_slice())
        .ok()
        .and_then(|c| c.not_after)
        .is_some_and(|t| t.seconds * 1000 > chrono::Utc::now().timestamp_millis())
}

#[tonic::async_trait]
impl SensorLinkService for Gateway {
    type StreamStream = Pin<Box<dyn Stream<Item = Result<StreamResponse, Status>> + Send>>;

    async fn stream(&self, req: Request<Streaming<StreamRequest>>) -> Result<Response<Self::StreamStream>, Status> {
        let id = identity::from_request(&req)?;
        let key = (id.tenant_id.clone(), id.device_id.clone());
        tracing::info!(tenant = %id.tenant_id, device = %id.device_id, "sensor connected");
        let (tx, rx) = mpsc::channel(64);
        let backlog = {
            let mut r = self.reg.lock().unwrap();
            r.streams.insert(key.clone(), tx.clone());
            r.pending.remove(&key).unwrap_or_default()
        };
        for sc in backlog.into_iter().filter(not_expired) {
            let _ = tx.send(Ok(StreamResponse { msg: Some(stream_response::Msg::Command(sc)) })).await;
        }

        let mut inbound = req.into_inner();
        let bus = self.bus.clone();
        let reg = self.reg.clone();
        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::info!(device = %id.device_id, error = %e, "stream ended");
                        break;
                    }
                };
                if let Err(e) = handle(&bus, &reg, &id, &tx, msg).await {
                    tracing::error!(device = %id.device_id, error = %e, "failed to handle sensor message");
                }
            }
            let still_current = {
                let mut r = reg.lock().unwrap();
                let current = r.streams.get(&key).is_some_and(|t| t.same_channel(&tx));
                if current {
                    r.streams.remove(&key);
                }
                current
            };
            if still_current {
                let v = serde_json::json!({ "tenant_id": id.tenant_id, "device_id": id.device_id, "event": "offline" });
                let headers = [("tenant_id", id.tenant_id.as_str()), ("device_id", id.device_id.as_str())];
                let _ = bus.publish(T_DEVICES, vec![(id.device_id.as_bytes().to_vec(), v.to_string().into_bytes())], &headers).await;
            }
            tracing::info!(device = %id.device_id, "sensor disconnected");
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn enroll(&self, _req: Request<EnrollRequest>) -> Result<Response<EnrollResponse>, Status> {
        // Renewal requires the issuing CA in KMS; dev certs come from `devpki`.
        Err(Status::unimplemented("certificate renewal is not available in the dev gateway"))
    }
}

async fn handle(
    bus: &Bus,
    reg: &Mutex<Registry>,
    id: &identity::DeviceIdentity,
    tx: &Tx,
    msg: StreamRequest,
) -> anyhow::Result<()> {
    let headers = [("tenant_id", id.tenant_id.as_str()), ("device_id", id.device_id.as_str())];
    match msg.msg {
        Some(stream_request::Msg::Hello(h)) => {
            tracing::info!(device = %id.device_id, version = %h.sensor_version, last_seq = h.last_seq, model = %h.edge_model_version, "hello");
            let v = serde_json::json!({
                "tenant_id": id.tenant_id, "device_id": id.device_id, "event": "online",
                "sensor_version": h.sensor_version, "os": h.os, "edge_model_version": h.edge_model_version,
            });
            bus.publish(T_DEVICES, vec![(id.device_id.as_bytes().to_vec(), serde_json::to_vec(&v)?)], &headers).await?;
        }
        Some(stream_request::Msg::Batch(mut b)) => {
            let key = (id.tenant_id.clone(), id.device_id.clone());
            let mut max_seq = 0;
            {
                let mut r = reg.lock().unwrap();
                let last = r.last_seq.get(&key).copied().unwrap_or(0);
                if let Some(first) = b.events.first() {
                    if last > 0 && first.seq > last + 1 {
                        tracing::warn!(device = %id.device_id, last, next = first.seq, "telemetry sequence gap");
                    }
                }
                for e in &mut b.events {
                    e.device_id = id.device_id.clone(); // never trust the payload's identity
                    max_seq = max_seq.max(e.seq);
                }
                r.last_seq.insert(key, max_seq.max(last));
            }
            if b.dropped_since_last > 0 {
                tracing::warn!(device = %id.device_id, dropped = b.dropped_since_last, "sensor dropped events");
            }
            let records = b.events.iter().map(|e| (id.device_id.as_bytes().to_vec(), e.encode_to_vec())).collect();
            bus.publish(T_TELEMETRY, records, &headers).await?;
            tx.send(Ok(StreamResponse { msg: Some(stream_response::Msg::AckSeq(max_seq)) })).await.ok();
        }
        Some(stream_request::Msg::Alert(mut a)) => {
            a.device_id = id.device_id.clone();
            let v = convert::alert_json(&a, &id.tenant_id);
            tracing::info!(device = %id.device_id, alert = %a.alert_id, "alert");
            bus.publish(T_ALERTS, vec![(id.device_id.as_bytes().to_vec(), serde_json::to_vec(&v)?)], &headers).await?;
        }
        Some(stream_request::Msg::CommandResult(r)) => {
            let v = convert::result_json(&r, &id.tenant_id, &id.device_id);
            tracing::info!(device = %id.device_id, command = %r.command_id, status = r.status, reason = %r.reason, "command result");
            bus.publish(T_RESULTS, vec![(id.device_id.as_bytes().to_vec(), serde_json::to_vec(&v)?)], &headers).await?;
        }
        Some(stream_request::Msg::ScanProgress(p)) => {
            let v = convert::scan_json(&p, &id.tenant_id, &id.device_id);
            tracing::info!(device = %id.device_id, scan = %p.scan_id, state = p.state, seen = p.files_seen, findings = p.findings, "scan progress");
            bus.publish(T_SCANS, vec![(id.device_id.as_bytes().to_vec(), serde_json::to_vec(&v)?)], &headers).await?;
        }
        Some(stream_request::Msg::Heartbeat(h)) => {
            tracing::debug!(device = %id.device_id, seq = h.seq, "heartbeat");
        }
        None => {}
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct CommandEnvelope {
    tenant_id: String,
    device_id: String,
    signed_command_b64: String,
}

/// Routes signed commands from the API to connected sensors. The gateway does
/// not verify signatures (the sensor does); it only checks routing consistency.
async fn route_commands(bus: Arc<Bus>, reg: Arc<Mutex<Registry>>) -> anyhow::Result<()> {
    let mut stream = bus.subscribe_latest(T_COMMANDS).await?;
    while let Some(value) = stream.recv().await {
        let env: CommandEnvelope = match serde_json::from_slice(&value) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "malformed command envelope");
                continue;
            }
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&env.signed_command_b64) else { continue };
        let Ok(sc) = SignedCommand::decode(bytes.as_slice()) else { continue };
        match RemediationCommand::decode(sc.command.as_slice()) {
            Ok(c) if c.device_id == env.device_id => {}
            _ => {
                tracing::warn!(device = %env.device_id, "command device_id does not match envelope; dropped");
                continue;
            }
        }
        let key = (env.tenant_id, env.device_id);
        let tx = reg.lock().unwrap().streams.get(&key).cloned();
        match tx {
            Some(tx) => {
                tracing::info!(device = %key.1, "delivering command");
                tx.send(Ok(StreamResponse { msg: Some(stream_response::Msg::Command(sc)) })).await.ok();
            }
            None => {
                tracing::info!(device = %key.1, "device offline; command queued");
                let mut r = reg.lock().unwrap();
                let q = r.pending.entry(key).or_default();
                q.retain(not_expired);
                if q.len() < 100 {
                    q.push(sc);
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let read = |f: &str| std::fs::read(args.pki.join(f)).with_context(|| format!("reading {f} (run `devpki init`)"));
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(read("gateway.pem")?, read("gateway.key")?))
        .client_ca_root(Certificate::from_pem(read("ca.pem")?));

    let bus = Arc::new(Bus::connect(&args.kafka, &[T_TELEMETRY, T_ALERTS, T_RESULTS, T_COMMANDS, T_SCANS, T_DEVICES]).await?);
    let reg = Arc::new(Mutex::new(Registry::default()));
    {
        let (bus, reg) = (bus.clone(), reg.clone());
        tokio::spawn(async move {
            if let Err(e) = route_commands(bus, reg).await {
                tracing::error!(error = %e, "command router stopped");
            }
        });
    }
    tracing::info!(listen = %args.listen, kafka = %args.kafka, "ingest-gateway up (mTLS required)");
    Server::builder()
        .tls_config(tls)?
        .add_service(SensorLinkServiceServer::new(Gateway { bus, reg }))
        .serve(args.listen.parse()?)
        .await?;
    Ok(())
}
