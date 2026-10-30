# LLM tool schemas

Single source of truth for every function the cloud agents may call (see ADR 0002).

- Files are sent to the OpenAI API as-is (`strict: true`), and `agents/scanu_agents/tools/registry.py` re-validates every call against the same schema.
- Only keywords that OpenAI strict mode supports are allowed here (`pattern`, `enum`, `minimum`/`maximum`, `minItems`/`maxItems`). Length limits (`explanation` ≤ 1200 chars, `narrative` ≤ 2000) are enforced server-side in `registry.py`.
- Entity IDs are `<kind>_<32 hex>`, derived deterministically by `ingest/writers` (see `entity_id()`). The guard rejects any ID that is not in the current incident's tenant subgraph.
