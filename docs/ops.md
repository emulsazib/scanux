# Scanu — Operations

## 1. Multi-tenant isolation model
| Layer | Isolation |
|---|---|
| Identity | Every device cert carries `URI:spiffe://scanu/tenant/<tenant_id>/device/<device_id>` SAN. Gateway extracts both; payload values are ignored. |
| Kafka | Shared topics, message key = `device_id`, header `tenant_id` set by gateway only. Consumers never trust payload tenant. |
| ClickHouse | `ocsf_events` `ORDER BY (tenant_id, device_id, time)`; per-tenant row policy for read users; writers use a separate insert-only role. |
| Neo4j | MVP: every node/rel has `tenant_id`; all queries go through `agents/scanu_agents/graphdb.py` which injects `$tenant_id`. Scale-out: database-per-tenant (Enterprise) for large tenants. |
| Postgres | RLS on every tenant table: `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. App sets `SET LOCAL app.tenant_id` per transaction. Superuser bypass role used only by migrations. |
| LLM | Requests never mix tenants; pseudonymization map stored per tenant. |

## 2. Keys & certificates
| Key | Location | Rotation |
|---|---|---|
| Root CA | Offline (HSM/air-gapped) | 10 y; pinned in sensor; two roots pinned to allow overlap |
| Issuing CA | KMS | 1 y |
| Gateway server cert | KMS / cert-manager | 90 d, automated |
| Device cert | TPM (NCrypt PCP, non-exportable) | 30 d auto-renew over existing mTLS session (`Enroll` RPC with CSR signed by current key) |
| Command signing (Ed25519) | KMS/HSM, sign-only service account | 180 d; sensors pin **current + next** `key_id`; new key announced in signed config before cutover |
| Vault master key | TPM-sealed (dev: DPAPI machine scope) | Per device; re-wrap per-file keys on rotation |

Revocation: gateway checks device serial against a deny-list in Postgres (pushed to an in-memory set, refreshed every 30 s). Short cert lifetime limits blast radius.

## 3. Privacy: what leaves the device
| Data | Default | Notes |
|---|---|---|
| File hashes, sizes, PE metadata, signer | Sent | |
| File paths | Sent, with user profile segment pseudonymized (`C:\Users\<u:7f3a>\...`) | |
| Process command lines | Sent, truncated 1 KB, secrets regex-scrubbed (tokens, passwords in args) | |
| Network: remote IP/port, DNS names, bytes | Sent | No payloads; TLS never decrypted |
| PowerShell script blocks | Hash + first 2 KB, scrubbed | Opt-out per tenant |
| File contents / memory dumps | **Never by default** | Per-incident opt-in by user, encrypted to tenant key |
| Data sent to OpenAI | Pseudonymized incident subgraph only | ZDR agreement required for production |

Legal flags: process/memory inspection and TLS metadata fingerprinting require clear EULA consent; EU deployments need a DPIA (GDPR Art. 35) and a DPA with the LLM provider; employers deploying on staff machines take on monitoring-law obligations (e.g. works-council consultation in DE).

## 4. Retention
| Store | Retention | Mechanism |
|---|---|---|
| Endpoint spool | 256 MB ring | eviction by priority |
| ClickHouse raw events | 30 d | `TTL time + INTERVAL 30 DAY` |
| Neo4j graph | 30 d (non-incident nodes), incident subgraphs 1 y | nightly job |
| Postgres incidents/actions | 1 y | partition drop |
| Audit log | 7 y | append-only, hash-chained, exported to WORM storage |
| Vault (endpoint) | 30 d after final decision, then secure delete | sensor janitor |

## 5. Incident audit log
Table `audit_log(id, tenant_id, at, actor, kind, subject, payload_json, prev_hash, hash)`; `hash = SHA-256(prev_hash || canonical_json(row))`.
Every HITL transition, command signature, and rollback writes a row. `GET /v1/audit/verify` recomputes the chain.

## 6. Running locally (dev)
See `README.md` at repo root.
