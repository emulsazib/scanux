"""Business logic shared by routes and consumers."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime

from . import audit, bus
from .hitl import Choice, PlannedCommand, State, check_transition, plan_commands, plan_rollback
from .signer import CommandSigner

log = logging.getLogger("scanu.service")
signer: CommandSigner | None = None

INCIDENT_RE = re.compile(r"^inc_[0-9a-f]{32}$")


class NotFound(Exception):
    pass


async def transition(cur, tenant_id: str, action_id: str, target: State, actor: str, why: dict) -> None:
    await cur.execute("SELECT state FROM actions WHERE action_id = %s FOR UPDATE", (action_id,))
    row = await cur.fetchone()
    check_transition(row["state"], target)
    await cur.execute("UPDATE actions SET state = %s, updated_at = now() WHERE action_id = %s", (target, action_id))
    await audit.append(cur, tenant_id, actor, "action.transition", action_id, {"from": row["state"], "to": target, **why})


async def send_commands(cur, tenant_id: str, action: dict, decision_id: str, planned: list[PlannedCommand], actor: str) -> list[str]:
    assert signer is not None, "command signer not configured (run `make pki`)"
    ids = []
    for pc in planned:
        s = signer.sign(pc, device_id=action["device_id"], action_id=action["action_id"], approval_ref=decision_id)
        await cur.execute(
            "INSERT INTO commands (command_id, tenant_id, action_id, decision_id, device_id, tool, args, nonce, key_id, not_after) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (s.command_id, tenant_id, action["action_id"], decision_id, action["device_id"], pc.tool,
             audit.canonical(pc.args), s.nonce, signer.key_id, datetime.fromtimestamp(s.not_after_s, UTC)),
        )
        await audit.append(cur, tenant_id, actor, "command.signed", s.command_id, {"tool": pc.tool, "args": pc.args, "key_id": signer.key_id})
        await bus.publish_command(tenant_id, action["device_id"], s.envelope_b64)
        ids.append(s.command_id)
    return ids


async def decide(cur, tenant_id: str, user_id: str, action_id: str, choice: Choice, channel: str, assertion: bytes | None) -> dict:
    await cur.execute("SELECT * FROM actions WHERE action_id = %s FOR UPDATE", (action_id,))
    action = await cur.fetchone()
    if action is None:
        raise NotFound(action_id)
    decision_id = f"dec_{uuid.uuid4().hex}"
    await cur.execute(
        "INSERT INTO decisions (decision_id, tenant_id, action_id, choice, user_id, channel, webauthn_assertion) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (decision_id, tenant_id, action_id, choice, user_id, channel, assertion),
    )
    actor = f"user:{user_id}"
    await audit.append(cur, tenant_id, actor, "hitl.decision", action_id, {"decision_id": decision_id, "choice": choice, "channel": channel})
    if choice == Choice.REJECT:
        await transition(cur, tenant_id, action_id, State.REJECTED, actor, {"decision_id": decision_id})
        return {"decision_id": decision_id, "state": State.REJECTED, "commands": []}

    await cur.execute("SELECT graph FROM incidents WHERE incident_id = %s", (action["incident_id"],))
    graph = (await cur.fetchone())["graph"]
    planned = plan_commands(choice, action["proposal"], graph)
    await transition(cur, tenant_id, action_id, State.APPROVED, actor, {"decision_id": decision_id, "choice": choice})
    if not planned:
        await transition(cur, tenant_id, action_id, State.FAILED, "system", {"reason": "no resolvable targets"})
        return {"decision_id": decision_id, "state": State.FAILED, "commands": []}
    ids = await send_commands(cur, tenant_id, action, decision_id, planned, actor)
    return {"decision_id": decision_id, "state": State.APPROVED, "commands": ids}


async def rollback(cur, tenant_id: str, user_id: str, action_id: str) -> dict:
    await cur.execute("SELECT * FROM actions WHERE action_id = %s FOR UPDATE", (action_id,))
    action = await cur.fetchone()
    if action is None:
        raise NotFound(action_id)
    if action["state"] != State.VERIFIED or action["rollback_pending"]:
        raise ValueError(f"rollback requires VERIFIED (is {action['state']})")
    await cur.execute("SELECT tool, args, vault_id FROM commands WHERE action_id = %s AND status = 'executed'", (action_id,))
    planned = plan_rollback(await cur.fetchall())
    if not planned:
        raise ValueError("nothing reversible (terminate cannot be undone)")
    decision_id = f"dec_{uuid.uuid4().hex}"
    await cur.execute(
        "INSERT INTO decisions (decision_id, tenant_id, action_id, choice, user_id, channel) VALUES (%s,%s,%s,'rollback',%s,'web')",
        (decision_id, tenant_id, action_id, user_id),
    )
    await cur.execute("UPDATE actions SET rollback_pending = true, updated_at = now() WHERE action_id = %s", (action_id,))
    await audit.append(cur, tenant_id, f"user:{user_id}", "hitl.rollback", action_id, {"decision_id": decision_id})
    ids = await send_commands(cur, tenant_id, action, decision_id, planned, f"user:{user_id}")
    return {"decision_id": decision_id, "commands": ids}


async def on_command_result(cur, tenant_id: str, r: dict) -> None:
    await cur.execute(
        "UPDATE commands SET status = %s, reason = %s, vault_id = %s, completed_at = now() WHERE command_id = %s RETURNING action_id, decision_id",
        (r["status"], r.get("reason", ""), r.get("vault_id", ""), r["command_id"]),
    )
    row = await cur.fetchone()
    if row is None:
        await on_scan_command_result(cur, tenant_id, r)
        return
    await audit.append(cur, tenant_id, f"device:{r['device_id']}", "command.result", r["command_id"],
                       {"status": r["status"], "reason": r.get("reason", ""), "vault_id": r.get("vault_id", "")})
    await cur.execute("SELECT status FROM commands WHERE decision_id = %s", (row["decision_id"],))
    statuses = [x["status"] for x in await cur.fetchall()]
    if "sent" in statuses:
        return
    await cur.execute("SELECT state, rollback_pending FROM actions WHERE action_id = %s FOR UPDATE", (row["action_id"],))
    action = await cur.fetchone()
    ok = all(s == "executed" for s in statuses)
    aid = row["action_id"]
    if action["rollback_pending"]:
        await cur.execute("UPDATE actions SET rollback_pending = false WHERE action_id = %s", (aid,))
        if ok:
            await transition(cur, tenant_id, aid, State.ROLLED_BACK, "system", {"decision_id": row["decision_id"]})
        else:
            await audit.append(cur, tenant_id, "system", "hitl.rollback_failed", aid, {"statuses": statuses})
    elif action["state"] == State.APPROVED:
        if ok:
            await transition(cur, tenant_id, aid, State.EXECUTED, "system", {})
            # Each executed result already includes the on-device post-condition check.
            await transition(cur, tenant_id, aid, State.VERIFIED, "system", {"postconditions": "device-verified"})
        else:
            await transition(cur, tenant_id, aid, State.FAILED, "system", {"statuses": statuses})


def validate_incident(body: dict) -> None:
    inc, prop = body["incident"], body["proposal"]
    if not INCIDENT_RE.match(inc["incident_id"]):
        raise ValueError("bad incident_id")
    node_ids = {n["id"] for n in inc["graph"].get("nodes", [])}
    for step in prop.get("steps", []):
        if step["target_entity_id"] not in node_ids:
            raise ValueError(f"proposal target {step['target_entity_id']} not in incident graph")
    if len(prop.get("explanation", "")) > 1200 or len(inc.get("narrative", "")) > 2000:
        raise ValueError("text too long")
    if prop.get("recommended_choice") not in {c.value for c in Choice if c != Choice.REJECT}:
        raise ValueError("bad recommended_choice")


async def upsert_incident(cur, body: dict) -> dict:
    validate_incident(body)
    t, inc, prop = body["tenant_id"], body["incident"], body["proposal"]
    await cur.execute(
        """INSERT INTO incidents (incident_id, tenant_id, device_id, title, severity, narrative, attack_techniques,
                                  member_entity_ids, alert_ids, graph, produced_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (incident_id) DO UPDATE SET title = EXCLUDED.title, severity = EXCLUDED.severity,
               narrative = EXCLUDED.narrative, attack_techniques = EXCLUDED.attack_techniques,
               member_entity_ids = EXCLUDED.member_entity_ids,
               alert_ids = (SELECT array_agg(DISTINCT a) FROM unnest(incidents.alert_ids || EXCLUDED.alert_ids) a),
               graph = EXCLUDED.graph, produced_by = EXCLUDED.produced_by
           RETURNING (xmax = 0) AS inserted""",
        (inc["incident_id"], t, body["device_id"], inc["title"], inc["severity"], inc["narrative"],
         inc["attack_techniques"], inc["member_entity_ids"], body["alert_ids"], audit.canonical(inc["graph"]), body["produced_by"]),
    )
    inserted = (await cur.fetchone())["inserted"]
    await cur.execute("UPDATE alerts SET incident_id = %s WHERE alert_id = ANY(%s)", (inc["incident_id"], body["alert_ids"]))
    await cur.execute("SELECT action_id, state FROM actions WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (inc["incident_id"],))
    existing = await cur.fetchone()
    if existing and existing["state"] == State.PROPOSED:
        await cur.execute(
            "UPDATE actions SET proposal = %s, explanation = %s, recommended_choice = %s, updated_at = now() WHERE action_id = %s",
            (audit.canonical(prop), prop["explanation"], prop["recommended_choice"], existing["action_id"]),
        )
        action_id = existing["action_id"]
    elif existing is None:
        action_id = f"act_{uuid.uuid4().hex}"
        await cur.execute(
            "INSERT INTO actions (action_id, tenant_id, incident_id, device_id, state, recommended_choice, proposal, explanation) "
            "VALUES (%s,%s,%s,%s,'PROPOSED',%s,%s,%s)",
            (action_id, t, inc["incident_id"], body["device_id"], prop["recommended_choice"], audit.canonical(prop), prop["explanation"]),
        )
    else:
        action_id = existing["action_id"]  # already decided; keep history, don't re-propose
    await audit.append(cur, t, f"service:{body['produced_by']}", "incident.upsert", inc["incident_id"],
                       {"inserted": inserted, "action_id": action_id, "severity": inc["severity"]})
    return {"incident_id": inc["incident_id"], "action_id": action_id, "inserted": inserted}


# ------------------------------------------------------------------- scans

SCAN_SCOPES = {"quick": 1, "full": 2}  # scan.proto ScanScope
TERMINAL = ("completed", "cancelled", "failed")


async def request_scan(cur, tenant_id: str, user_id: str, device_id: str, scope: str) -> dict:
    await cur.execute("SELECT device_id FROM devices WHERE device_id = %s", (device_id,))
    if await cur.fetchone() is None:
        raise NotFound(device_id)
    await cur.execute(
        "SELECT scan_id FROM scans WHERE device_id = %s AND state IN ('queued', 'running') AND updated_at > now() - interval '30 minutes'",
        (device_id,),
    )
    if (busy := await cur.fetchone()) is not None:
        raise ValueError(f"scan {busy['scan_id']} is already running on {device_id}")
    scan_id = f"scn_{uuid.uuid4().hex}"
    await cur.execute(
        "INSERT INTO scans (scan_id, tenant_id, device_id, scope, state, requested_by) VALUES (%s,%s,%s,%s,'queued',%s) RETURNING *",
        (scan_id, tenant_id, device_id, scope, user_id),
    )
    scan = await cur.fetchone()
    await _send_scan_command(cur, tenant_id, user_id, device_id, scan_id,
                             PlannedCommand("start_scan", {"scan_id": scan_id, "scope": SCAN_SCOPES[scope]}), action_id=scan_id)
    await audit.append(cur, tenant_id, f"user:{user_id}", "scan.requested", scan_id, {"device_id": device_id, "scope": scope})
    return scan


async def cancel_scan(cur, tenant_id: str, user_id: str, scan_id: str) -> dict:
    await cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
    scan = await cur.fetchone()
    if scan is None:
        raise NotFound(scan_id)
    if scan["state"] in TERMINAL:
        raise ValueError(f"scan is already {scan['state']}")
    await _send_scan_command(cur, tenant_id, user_id, scan["device_id"], scan_id,
                             PlannedCommand("cancel_scan", {"scan_id": scan_id}), action_id=f"cancel:{scan_id}")
    await audit.append(cur, tenant_id, f"user:{user_id}", "scan.cancel_requested", scan_id, {})
    return scan


async def _send_scan_command(cur, tenant_id, user_id, device_id, scan_id, pc: PlannedCommand, action_id: str) -> None:
    assert signer is not None, "command signer not configured (run `make pki`)"
    s = signer.sign(pc, device_id=device_id, action_id=action_id, approval_ref=scan_id)
    await audit.append(cur, tenant_id, f"user:{user_id}", "command.signed", s.command_id, {"tool": pc.tool, "args": pc.args, "key_id": signer.key_id})
    await bus.publish_command(tenant_id, device_id, s.envelope_b64)


async def on_scan_command_result(cur, tenant_id: str, r: dict) -> None:
    action = r.get("action_id", "")
    if action.startswith("scn_") and r["status"] != "executed":
        await cur.execute(
            "UPDATE scans SET state = 'failed', error = %s, updated_at = now() WHERE scan_id = %s AND state IN ('queued', 'running')",
            (r.get("reason", "") or r["status"], action),
        )
    elif not action.startswith(("scn_", "cancel:scn_")):
        log.warning("result for unknown command %s", r["command_id"])
        return
    await audit.append(cur, tenant_id, f"device:{r['device_id']}", "command.result", r["command_id"],
                       {"status": r["status"], "reason": r.get("reason", ""), "action_id": action})


async def on_scan_progress(cur, tenant_id: str, p: dict) -> None:
    """Upserts progress; terminal states are never overwritten by late RUNNING updates.
    Device-initiated (local) scans appear here first."""
    to_ts = lambda ms: datetime.fromtimestamp(ms / 1000, UTC) if ms else None  # noqa: E731
    await cur.execute(
        """INSERT INTO scans (scan_id, tenant_id, device_id, scope, state, requested_by, files_seen, files_analyzed,
                              bytes_analyzed, findings, current_path, error, started_at, finished_at)
           VALUES (%(scan_id)s, %(tenant_id)s, %(device_id)s, %(scope)s, %(state)s, 'device', %(files_seen)s, %(files_analyzed)s,
                   %(bytes_analyzed)s, %(findings)s, %(current_path)s, %(error)s, %(started)s, %(finished)s)
           ON CONFLICT (scan_id) DO UPDATE SET
               state = EXCLUDED.state, files_seen = EXCLUDED.files_seen, files_analyzed = EXCLUDED.files_analyzed,
               bytes_analyzed = EXCLUDED.bytes_analyzed, findings = EXCLUDED.findings, current_path = EXCLUDED.current_path,
               error = EXCLUDED.error, started_at = COALESCE(scans.started_at, EXCLUDED.started_at),
               finished_at = EXCLUDED.finished_at, updated_at = now()
           WHERE scans.state NOT IN ('completed', 'cancelled', 'failed')
           RETURNING state""",
        {**p, "scope": p.get("scope", "quick"), "tenant_id": tenant_id, "started": to_ts(p.get("started_at_ms")), "finished": to_ts(p.get("finished_at_ms"))},
    )
    row = await cur.fetchone()
    if row and row["state"] in TERMINAL:
        await audit.append(cur, tenant_id, f"device:{p['device_id']}", f"scan.{row['state']}", p["scan_id"],
                           {"files_seen": p["files_seen"], "files_analyzed": p["files_analyzed"], "findings": p["findings"]})


async def on_device_event(cur, tenant_id: str, e: dict) -> None:
    online = e["event"] == "online"
    await cur.execute(
        """INSERT INTO devices (tenant_id, device_id, online, sensor_version, os) VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (tenant_id, device_id) DO UPDATE SET online = EXCLUDED.online, last_seen = now(),
               sensor_version = COALESCE(NULLIF(EXCLUDED.sensor_version, ''), devices.sensor_version),
               os = COALESCE(NULLIF(EXCLUDED.os, ''), devices.os)""",
        (tenant_id, e["device_id"], online, e.get("sensor_version", ""), e.get("os", "")),
    )


# ----------------------------------------------------------------- profile

async def get_profile(cur, tenant_id: str, user_id: str, role: str) -> dict:
    await cur.execute(
        "INSERT INTO users (tenant_id, user_id, display_name) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
        (tenant_id, user_id, user_id),
    )
    await cur.execute("SELECT display_name, email, notify_desktop, notify_email_critical, updated_at FROM users WHERE user_id = %s", (user_id,))
    profile = await cur.fetchone()
    return {"user_id": user_id, "role": role, "tenant_id": tenant_id, **profile}


async def update_profile(cur, tenant_id: str, user_id: str, role: str, changes: dict) -> dict:
    await get_profile(cur, tenant_id, user_id, role)
    if changes:
        cols = ", ".join(f"{k} = %({k})s" for k in changes)  # keys come from a fixed pydantic model
        await cur.execute(f"UPDATE users SET {cols}, updated_at = now() WHERE user_id = %(user_id)s", {**changes, "user_id": user_id})
        await audit.append(cur, tenant_id, f"user:{user_id}", "profile.updated", user_id, {"fields": sorted(changes)})
    return await get_profile(cur, tenant_id, user_id, role)
