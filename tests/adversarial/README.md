# Adversarial tests

Abuse cases from [docs/threat-model.md](../../docs/threat-model.md) §3, and where each one is exercised.

| # | Attack | Test | Runs on |
|---|---|---|---|
| A1–A3 | Prompt injection via filename / script block / DNS → LLM | `agents/tests/test_agents.py::test_prompt_injection_cannot_escape_schema`, `test_registry_rejects_bad_calls`, `test_redaction_neutralizes_delimiter_breakout`; the e2e scenario's script block carries a live injection string | Mac / CI |
| A4 | Replay a captured command | `enforcer::verify::tests::rejects_replay_expiry_and_device_mismatch`, `nonce_store_survives_restart` | Mac / CI |
| A5 | Forge command with an attacker key | `enforcer::verify::tests::rejects_forged_unknown_key_and_tampered`; e2e step 6 (real Kafka → gateway → sensor, `BAD_SIGNATURE`) | Mac / CI + e2e |
| A6 | Command for another device | `rejects_replay_expiry_and_device_mismatch`; gateway drops envelope/command device mismatch | Mac / CI |
| A7 | Destructive command without approval | `non_tier1_tools_need_approval`, `engine::tests::pid_reuse_and_unapproved_commands_fail` | Mac / CI |
| A8 | Ransomware hits canary | `engine::tests::canary_write_freezes_process_under_100ms`; e2e step 7; `tests/perf/canary.ps1` (kernel path) | Mac + Windows VM |
| A9 | PID reuse | `pid_reuse_and_unapproved_commands_fail` | Mac / CI |
| A10 | Vault tamper | `vault::tests::{tampered_blob_fails_restore, edited_index_is_detected, wrong_master_key_fails}` | Mac / CI |
| A11 | Cross-tenant read/write | `api/tests/test_rls.py` (`SCANU_TEST_PG=1`) | Mac with `make up` |
| A12 | Spoofed device identity | `ingest-gateway identity::tests::parses_only_well_formed_identities`; gateway overwrites payload `device_id` | Mac / CI |
| — | Kill / suspend / inject into the sensor | `taskkill /f`, `OpenProcess(PROCESS_TERMINATE)`, `fltmc unload` must fail (sensor/driver-win/README.md § Verify) | Windows VM |
| — | Out-of-schema tool from LLM | `test_registry_rejects_bad_calls` (extra props, unknown enum, bad pattern, non-graph target, over-length) | Mac / CI |
