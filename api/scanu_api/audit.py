"""Hash-chained, append-only audit log (per tenant)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "genesis"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def row_hash(prev_hash: str, actor: str, kind: str, subject: str, payload: dict) -> str:
    body = canonical({"prev": prev_hash, "actor": actor, "kind": kind, "subject": subject, "payload": payload})
    return hashlib.sha256(body.encode()).hexdigest()


async def append(cur, tenant_id: str, actor: str, kind: str, subject: str, payload: dict) -> str:
    # Serialize appends per tenant without needing UPDATE privilege (the table is append-only).
    await cur.execute("SELECT pg_advisory_xact_lock(hashtext('audit:' || %s))", (tenant_id,))
    await cur.execute("SELECT hash FROM audit_log WHERE tenant_id = %s ORDER BY id DESC LIMIT 1", (tenant_id,))
    row = await cur.fetchone()
    prev = row["hash"] if row else GENESIS
    h = row_hash(prev, actor, kind, subject, payload)
    await cur.execute(
        "INSERT INTO audit_log (tenant_id, actor, kind, subject, payload, prev_hash, hash) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (tenant_id, actor, kind, subject, canonical(payload), prev, h),
    )
    return h


def verify_chain(rows: list[tuple[str, str, str, dict, str, str]]) -> tuple[bool, int | None]:
    """rows: (actor, kind, subject, payload, prev_hash, hash) ordered by id. Returns (ok, first_bad_index)."""
    prev = GENESIS
    for i, (actor, kind, subject, payload, prev_hash, h) in enumerate(rows):
        if prev_hash != prev or row_hash(prev_hash, actor, kind, subject, payload) != h:
            return False, i
        prev = h
    return True, None
