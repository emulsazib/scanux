# ADR 0002 — OpenAI GPT API with strict tools and server-side validation

**Status:** accepted

## Context
The cloud agents need an LLM for correlation narratives and remediation proposals. Outputs must never
become arbitrary actions, and telemetry is attacker-controlled.

## Decision
- Provider: OpenAI GPT API. Model IDs come from `SCANU_LLM_REASONING` / `SCANU_LLM_FAST` env vars, never hard-coded.
- Every tool is defined once in `schemas/tools/*.json` with `strict: true` and `additionalProperties: false`.
- Belt and braces: even with provider-side strict mode, the agent re-validates each call against the same
  JSON Schema, then runs the entity-ID guard (targets must exist in the tenant's incident graph).
- The LLM proposes; the API (deterministic code) builds and signs `RemediationCommand`s after human approval.
- `LLMClient` is a small protocol, so tests use a fake and a different provider can be swapped in.

## Consequences
- Pseudonymized telemetry leaves our infrastructure. That requires ZDR terms and tenant opt-out (deterministic correlation only).
- A provider outage degrades explanations, not protection: Tier-1 is local, and correlation falls back to rule-based graph templates.
