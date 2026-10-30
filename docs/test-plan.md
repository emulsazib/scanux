# Scanu — Test Plan

## Layers

| Layer | What | Command | Where |
|---|---|---|---|
| Unit (Rust) | OCSF mapping, privacy scrubbing, detectors (DGA, tunnel, beacon, mass-modify), spool eviction/persistence, canaries, bloom FP rate, PE features, scorer, vault crypto + hash chain, command verification, executor post-conditions, gateway identity, writer graph projection | `make test-rust` | any |
| Unit (Python) | HITL transition table, choice→command planning, rollback inversion, Ed25519 signer round-trip, audit hash chain, tool-schema validation, entity guard, redaction, deterministic correlation, prompt injection | `make test-py` | any |
| Contract | Entity IDs identical in Rust and Python (`schemas/testvectors/entity_ids.json`); edge-model features identical in Rust and Python (`edge-ml/training/tests/test_parity.py`) | `cargo test -p ingest-writers`, `cd agents && uv run pytest`, `cd edge-ml/training && uv run pytest` | any |
| Integration | RLS cross-tenant isolation on real Postgres | `cd api && SCANU_TEST_PG=1 uv run pytest tests/test_rls.py` | `make up` |
| End to end | sensor-sim → mTLS gateway → Kafka → writers (ClickHouse, Neo4j) + agents → API → approval → signed command → sensor verify/execute → VERIFIED → rollback → ROLLED_BACK; forged command; ransomware freeze; audit verify | `make e2e` | `make up` + services |
| Windows type-check | All Win32/ETW/WFP/driver-port code | `make check-windows` | Mac/Linux |
| Windows runtime | Driver load, self-protection, canary kernel path, pre-exec block, WFP isolation, CPU budget | `tests/perf/*.ps1`, `sensor/driver-win/README.md` | Windows 11 VM |
| Adversarial | See `tests/adversarial/README.md` | — | mixed |

## MVP acceptance criteria → evidence

| Criterion | Evidence |
|---|---|
| Sensor collects file, process, network (PID-bound), logs; ≤ 2% idle / ≤ 5% p95 CPU | `sensor-win/src/etw.rs` + `eventlog.rs`; budget measured by `tests/perf/cpu.ps1` (**Windows VM; not yet measured**) |
| Offline edge classifier scores unknown executables before run | `engine::pre_exec` (tests `pre_exec_blocks_bloom_hit_and_alerts_on_suspicious`); kernel hook `CreateProcessNotifyEx` in `scanu_flt.c` |
| Canary trip freezes process in < 100 ms (local path) | engine path: 9–18 µs measured in `make sim-offline` / e2e; kernel path: `tests/perf/canary.ps1` (**Windows VM**) |
| Cloud agents produce incident graph + human-readable explanation | e2e step 2 (9 nodes / 10 edges, 6 ATT&CK techniques, plain-language narrative) |
| Tier-1 works offline; Tier-2/3 need cloud + user approval | `make sim-offline`; verifier rejects non-Tier-1 tools without `approval_ref`; API only signs after a decision row |
| User can scan the whole system on demand | e2e step 8 (full scan: 83 files, 43 analyzed, 2 findings → incident → quarantined → VERIFIED); engine tests for findings, exclusivity, cancel |
| Quarantine reversible from encrypted vault | `vault` tests; e2e step 5 (byte-identical restore) |
| LLM cannot invoke anything outside the validated tool schema | `agents/tests/test_agents.py`; closed `RemediationCommand.tool` oneof; API builds commands, not the LLM |
| mTLS + pinned certs agent↔cloud | gateway requires client cert from the pinned CA; sensor trusts only the bundled CA; device identity from SAN |

## CI (suggested)

```yaml
jobs:
  rust:    [cargo fmt --check, cargo clippy --workspace -D warnings, cargo test --workspace, make check-windows]
  python:  [cd api && uv run pytest, cd agents && uv run pytest, cd edge-ml/training && uv run pytest]
  web:     [pnpm -C web typecheck, pnpm -C web build]
  e2e:     [make up, start services, make e2e]          # nightly
  windows: [msbuild driver, verifier, tests/perf/*.ps1] # self-hosted Windows runner
```
