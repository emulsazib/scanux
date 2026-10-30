# Scanu

Hybrid EDR + AI-SIEM for personal computers. A privileged Windows sensor detects threats, freezes them in microseconds, and keeps working offline. A multi-tenant cloud correlates telemetry into incident graphs with an LLM, explains them in plain language, and lets a human decide. Every destructive step can be reversed.

**Design goal:** contain and recover, not perfect prevention.

- Architecture: [docs/system-design.md](docs/system-design.md)
- Threat model (STRIDE + abuse cases): [docs/threat-model.md](docs/threat-model.md)
- Operations (tenancy, keys, privacy, retention, audit): [docs/ops.md](docs/ops.md)
- Test plan: [docs/test-plan.md](docs/test-plan.md)

## What works today

| Area | Status |
|---|---|
| Wire formats: protobuf (telemetry, alerts, commands, HITL), OCSF extension, LLM tool schemas | ✅ `schemas/` |
| Engine: OCSF normalization, on-device pseudonymization, spool, DGA/tunnel/beacon/mass-modify/credential-store/script detectors, canaries, Tier-1 freeze, pre-exec scoring | ✅ tested on macOS via `sensor-sim` |
| Edge ML: SHA-256 → bloom → PE/ELF features → classifier (baseline linear; ONNX LightGBM behind `--features onnx`) → YARA-X (`--features yara`) | ✅ (no trained model shipped; see `edge-ml/training`) |
| Signed command verification (Ed25519, key pin, device binding, expiry, replay, approval) + executor with on-device post-conditions | ✅ |
| Encrypted vault (AES-256-GCM, hash-chained index, byte-identical restore) | ✅ |
| Cloud: mTLS gateway → Kafka → ClickHouse + Neo4j; LangGraph agents (OpenAI strict tools + deterministic fallback); FastAPI HITL state machine, RLS, audit chain | ✅ full e2e loop passes |
| On-demand **Quick / Full system scans** from the console or desktop app: live progress, cancel, findings → incident → quarantine | ✅ e2e tested (simulated endpoint) |
| Web console (Next.js) with **Settings** (API connection + test, profile, notifications); desktop tray client (Tauri) | ✅ builds / type-checks |
| Windows backend: ETW, Event Log, WFP isolation, NtSuspendProcess, DPAPI vault key, driver port client | ⚠️ type-checks for `x86_64-pc-windows-msvc`; **not yet run on Windows** |
| Minifilter (`scanu_flt.sys`): canaries, protected paths, pre-exec gate, ObCallbacks, anti-unload | ⚠️ written; **build and load in a Windows VM** ([guide](sensor/driver-win/README.md)) |
| TPM-backed device key, JA3/JA4, memory (RWX/hollowing) scanning, Linux/macOS backends, mobile push | ⏳ post-MVP |
| PPL + ELAM | ⛔ requires Microsoft Virus Initiative membership |

## Quick start (macOS / Linux dev machine)

Prerequisites: Rust (rustup), Docker, `uv`, `pnpm`, `protoc` (only for `make proto`).

```bash
make pki          # dev CA, gateway cert, command-signing key, device cert for dev-sim-1
make up           # Postgres, ClickHouse, Neo4j, Redpanda
make test         # Rust + Python unit/contract tests

# four terminals (or background them):
make gateway
make writers
make api          # http://127.0.0.1:8000  (dev token: dev-owner-token)
make agents       # set OPENAI_API_KEY, SCANU_LLM_REASONING, SCANU_LLM_FAST to enable the LLM

make e2e          # full loop: simulate attack → incident → approve → execute → verify → rollback
make web          # console at http://localhost:3000
make sim-cred     # replay the credential-theft chain, then approve it in the console
make sim-offline  # Tier-1 with no cloud at all
cargo run -p sensor-sim -- --device dev-sim-1 scenario dormant --linger 900
                  # plants dormant malware; click "Full system scan" on the Diagnostics page
```

Without OpenAI credentials, the agents use deterministic correlation, so every test and the e2e run need no API key.

## Windows

```powershell
cargo build --release -p sensor-svc           # scanu-sensor.exe
# driver: see sensor/driver-win/README.md (WDK, test-signing)
# config: C:\ProgramData\Scanu\sensor.json
#   { "device_id": "...", "gateway": "https://gateway:7443", "canary_dirs": ["C:\\Users\\<you>\\Documents"] }
# PKI:    C:\ProgramData\Scanu\pki\{ca.pem, device.pem, device.key, cmd-signing.pub.pem, cmd-signing.key_id}
sc.exe create ScanuSensor binPath= "C:\Program Files\Scanu\scanu-sensor.exe" start= auto obj= LocalSystem
sc.exe sdset ScanuSensor "D:(A;;CCLCSWRPLORC;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"   # admins can't stop it
```

`make check-windows` type-checks the Windows backend from macOS. `sensor-svc` itself links `ring` (C), so build it on Windows.

## Layout

```
schemas/        proto, OCSF extension, LLM tool schemas, cross-language test vectors
sensor/         Rust crates (core, engine, enforcer, vault, win/linux/macos backends, service, simulator) + C minifilter
edge-ml/        on-device static analysis crate, training pipeline, YARA rules
ingest/         mTLS gateway, Kafka bus, ClickHouse/Neo4j writers
agents/         LangGraph Perception → Correlation → Remediation
api/            FastAPI: incidents, HITL, signing, audit, RLS
web/ desktop/   Next.js console, Tauri tray client (shared tokens in packages/ui, from design/)
deploy/         docker-compose, dev PKI generator
tests/          e2e, adversarial map, Windows perf scripts
```

## Security notes for contributors

- Telemetry is attacker-controlled. Never interpret it, never render it as HTML, and never put it outside `<untrusted_data>` in a prompt.
- The sensor runs only the closed `RemediationCommand.tool` set. Adding a tool needs a schema change, a verifier/executor change, and review.
- `deploy/pki/out` holds **dev-only** keys. Production roots are offline, and the command-signing key lives in KMS/HSM.
