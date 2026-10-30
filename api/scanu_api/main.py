"""FastAPI app. Run: uv run uvicorn scanu_api.main:app --port 8000"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import audit, bus, db, service
from .config import settings
from .hitl import Choice, IllegalTransition
from .signer import CommandSigner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("scanu.api")

DEV_TENANT = "11111111-1111-4111-8111-111111111111"
DEV_TOKEN = "dev-owner-token"


async def _seed_dev() -> None:
    import psycopg

    async with await psycopg.AsyncConnection.connect(settings.database_url_admin, autocommit=True) as conn:
        await conn.execute("INSERT INTO tenants (tenant_id, name) VALUES (%s, 'Dev Tenant') ON CONFLICT DO NOTHING", (DEV_TENANT,))
        await conn.execute(
            "INSERT INTO api_tokens (token_sha256, tenant_id, user_id, role) VALUES (%s, %s, 'dev-owner', 'owner') ON CONFLICT DO NOTHING",
            (hashlib.sha256(DEV_TOKEN.encode()).hexdigest(), DEV_TENANT),
        )


async def _on_alert(a: dict) -> None:
    async with db.tenant_tx(a["tenant_id"]) as cur:
        await cur.execute(
            "INSERT INTO devices (tenant_id, device_id) VALUES (%s, %s) ON CONFLICT (tenant_id, device_id) DO UPDATE SET last_seen = now()",
            (a["tenant_id"], a["device_id"]),
        )
        await cur.execute(
            "INSERT INTO alerts (alert_id, tenant_id, device_id, severity, kind, tier1, payload) VALUES (%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            (a["alert_id"], a["tenant_id"], a["device_id"], a["severity"],
             a["reason"].get("name") or a["reason"]["kind"], a["tier1"], audit.canonical(a)),
        )


async def _on_result(r: dict) -> None:
    async with db.tenant_tx(r["tenant_id"]) as cur:
        await service.on_command_result(cur, r["tenant_id"], r)


async def _on_scan(p: dict) -> None:
    async with db.tenant_tx(p["tenant_id"]) as cur:
        await service.on_scan_progress(cur, p["tenant_id"], p)


async def _on_device(e: dict) -> None:
    async with db.tenant_tx(e["tenant_id"]) as cur:
        await service.on_device_event(cur, e["tenant_id"], e)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.migrate()
    if os.getenv("SCANU_DEV_SEED", "1") == "1":
        await _seed_dev()
    await db.open_pool()
    try:
        service.signer = CommandSigner.from_pki_dir(settings.pki_dir, settings.command_ttl_s)
    except FileNotFoundError:
        log.warning("no command-signing key in %s; approvals will fail until `make pki`", settings.pki_dir)
    await bus.start_producer()
    tasks = [
        asyncio.create_task(bus.consume(bus.T_ALERTS, "scanu-api-alerts", _on_alert)),
        asyncio.create_task(bus.consume(bus.T_RESULTS, "scanu-api-results", _on_result)),
        asyncio.create_task(bus.consume(bus.T_SCANS, "scanu-api-scans", _on_scan)),
        asyncio.create_task(bus.consume(bus.T_DEVICES, "scanu-api-devices", _on_device)),
    ]
    yield
    for t in tasks:
        t.cancel()
    await bus.stop_producer()
    await db.close_pool()


app = FastAPI(title="Scanu API", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["*"], allow_headers=["*"])


class Principal(BaseModel):
    tenant_id: str
    user_id: str
    role: str


async def principal(authorization: Annotated[str | None, Header()] = None) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer token required")
    sha = hashlib.sha256(authorization.removeprefix("Bearer ").encode()).hexdigest()
    async with db.global_cursor() as cur:
        await cur.execute("SELECT tenant_id, user_id, role FROM api_tokens WHERE token_sha256 = %s", (sha,))
        row = await cur.fetchone()
    if row is None:
        raise HTTPException(401, "invalid token")
    return Principal(**row)


def require_service(x_scanu_service_token: Annotated[str | None, Header()] = None) -> None:
    if x_scanu_service_token != settings.service_token:
        raise HTTPException(401, "service token required")


P = Annotated[Principal, Depends(principal)]


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "signer": service.signer.key_id if service.signer else None}


@app.get("/v1/stats")
async def stats(p: P) -> dict:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("""SELECT
            (SELECT count(*) FROM alerts WHERE received_at > now() - interval '7 days') AS alerts_7d,
            (SELECT count(*) FROM alerts WHERE tier1 <> 'none' AND received_at > now() - interval '7 days') AS frozen_7d,
            (SELECT count(*) FROM incidents) AS incidents,
            (SELECT count(*) FROM actions WHERE state = 'PROPOSED') AS pending_actions,
            (SELECT count(*) FROM actions WHERE state = 'VERIFIED') AS verified_actions,
            (SELECT count(*) FROM devices) AS devices""")
        return await cur.fetchone()


@app.get("/v1/alerts")
async def list_alerts(p: P, limit: int = Query(50, le=500)) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("SELECT alert_id, device_id, severity, kind, tier1, incident_id, received_at, payload FROM alerts ORDER BY received_at DESC LIMIT %s", (limit,))
        return await cur.fetchall()


@app.get("/v1/devices")
async def list_devices(p: P) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("SELECT device_id, online, sensor_version, os, first_seen, last_seen FROM devices ORDER BY online DESC, last_seen DESC")
        return await cur.fetchall()


@app.get("/v1/incidents")
async def list_incidents(p: P, limit: int = Query(50, le=500)) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute(
            """SELECT i.incident_id, i.device_id, i.title, i.severity, i.attack_techniques, i.created_at, i.produced_by,
                      a.action_id, a.state AS action_state, a.recommended_choice
               FROM incidents i LEFT JOIN LATERAL (
                   SELECT action_id, state, recommended_choice FROM actions WHERE incident_id = i.incident_id ORDER BY created_at DESC LIMIT 1
               ) a ON true
               ORDER BY i.created_at DESC LIMIT %s""",
            (limit,),
        )
        return await cur.fetchall()


@app.get("/v1/incidents/{incident_id}")
async def get_incident(incident_id: str, p: P) -> dict:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("SELECT * FROM incidents WHERE incident_id = %s", (incident_id,))
        inc = await cur.fetchone()
        if inc is None:
            raise HTTPException(404)
        await cur.execute("SELECT * FROM actions WHERE incident_id = %s ORDER BY created_at", (incident_id,))
        actions = await cur.fetchall()
        ids = [a["action_id"] for a in actions]
        await cur.execute("SELECT command_id, action_id, tool, args, status, reason, vault_id, created_at, completed_at FROM commands WHERE action_id = ANY(%s) ORDER BY created_at", (ids,))
        commands = await cur.fetchall()
        await cur.execute("SELECT alert_id, severity, kind, tier1, received_at, payload FROM alerts WHERE alert_id = ANY(%s) ORDER BY received_at", (inc["alert_ids"],))
        alerts = await cur.fetchall()
        return {"incident": inc, "actions": actions, "commands": commands, "alerts": alerts}


@app.get("/v1/actions")
async def list_actions(p: P, state: str | None = None) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        if state:
            await cur.execute("SELECT a.*, i.title, i.severity FROM actions a JOIN incidents i USING (incident_id) WHERE a.state = %s ORDER BY a.created_at DESC", (state,))
        else:
            await cur.execute("SELECT a.*, i.title, i.severity FROM actions a JOIN incidents i USING (incident_id) ORDER BY a.created_at DESC LIMIT 100")
        return await cur.fetchall()


class DecisionIn(BaseModel):
    choice: Choice
    channel: str = Field("web", pattern="^(web|desktop|mobile)$")
    webauthn_assertion_b64: str | None = None


@app.post("/v1/actions/{action_id}/decision")
async def decide(action_id: str, body: DecisionIn, p: P) -> dict:
    if p.role not in ("owner", "analyst"):
        raise HTTPException(403, "viewer cannot approve")
    assertion = base64.b64decode(body.webauthn_assertion_b64) if body.webauthn_assertion_b64 else None
    try:
        async with db.tenant_tx(p.tenant_id) as cur:
            return await service.decide(cur, p.tenant_id, p.user_id, action_id, body.choice, body.channel, assertion)
    except service.NotFound:
        raise HTTPException(404) from None
    except IllegalTransition as e:
        raise HTTPException(409, str(e)) from None


@app.post("/v1/actions/{action_id}/rollback")
async def rollback(action_id: str, p: P) -> dict:
    if p.role not in ("owner", "analyst"):
        raise HTTPException(403)
    try:
        async with db.tenant_tx(p.tenant_id) as cur:
            return await service.rollback(cur, p.tenant_id, p.user_id, action_id)
    except service.NotFound:
        raise HTTPException(404) from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None


@app.get("/v1/audit/verify")
async def audit_verify(p: P) -> dict:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("SELECT actor, kind, subject, payload, prev_hash, hash FROM audit_log ORDER BY id")
        rows = [(r["actor"], r["kind"], r["subject"], r["payload"], r["prev_hash"], r["hash"]) for r in await cur.fetchall()]
    ok, bad = audit.verify_chain(rows)
    return {"ok": ok, "rows": len(rows), "first_bad_index": bad}


@app.get("/v1/audit")
async def audit_list(p: P, limit: int = Query(100, le=1000)) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        await cur.execute("SELECT id, at, actor, kind, subject, payload, hash FROM audit_log ORDER BY id DESC LIMIT %s", (limit,))
        return await cur.fetchall()


@app.get("/v1/events")
async def events(p: P, device_id: str | None = None, limit: int = Query(100, le=1000)) -> list[dict[str, Any]]:
    """Raw OCSF from ClickHouse; tenant filter is a bound parameter."""
    q = "SELECT event_id, device_id, seq, class_uid, time, ocsf FROM scanu.ocsf_events WHERE tenant_id = {t:String}"
    params = {"param_t": p.tenant_id}
    if device_id:
        q += " AND device_id = {d:String}"
        params["param_d"] = device_id
    q += " ORDER BY time DESC LIMIT {n:UInt32} FORMAT JSON"
    params["param_n"] = str(limit)
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(settings.clickhouse_url, params=params, content=q,
                         headers={"X-ClickHouse-User": settings.clickhouse_user, "X-ClickHouse-Key": settings.clickhouse_password})
    if r.status_code != 200:
        raise HTTPException(502, "clickhouse unavailable")
    return r.json()["data"]


class ScanIn(BaseModel):
    scope: Literal["quick", "full"]


@app.post("/v1/devices/{device_id}/scans")
async def start_scan(device_id: str, body: ScanIn, p: P) -> dict:
    if p.role not in ("owner", "analyst"):
        raise HTTPException(403, "viewer cannot start scans")
    try:
        async with db.tenant_tx(p.tenant_id) as cur:
            return await service.request_scan(cur, p.tenant_id, p.user_id, device_id, body.scope)
    except service.NotFound:
        raise HTTPException(404, "unknown device") from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None


@app.post("/v1/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, p: P) -> dict:
    if p.role not in ("owner", "analyst"):
        raise HTTPException(403)
    try:
        async with db.tenant_tx(p.tenant_id) as cur:
            await service.cancel_scan(cur, p.tenant_id, p.user_id, scan_id)
            return {"scan_id": scan_id, "cancel": "requested"}
    except service.NotFound:
        raise HTTPException(404) from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None


@app.get("/v1/scans")
async def list_scans(p: P, device_id: str | None = None, limit: int = Query(20, le=200)) -> list[dict]:
    async with db.tenant_tx(p.tenant_id) as cur:
        if device_id:
            await cur.execute("SELECT * FROM scans WHERE device_id = %s ORDER BY created_at DESC LIMIT %s", (device_id, limit))
        else:
            await cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT %s", (limit,))
        return await cur.fetchall()


class ProfileIn(BaseModel):
    display_name: str | None = Field(None, min_length=1, max_length=80)
    email: str | None = Field(None, max_length=254, pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$")
    notify_desktop: bool | None = None
    notify_email_critical: bool | None = None


async def _with_tenant_name(profile: dict) -> dict:
    async with db.global_cursor() as cur:
        await cur.execute("SELECT name FROM tenants WHERE tenant_id = %s", (profile["tenant_id"],))
        profile["tenant_name"] = (await cur.fetchone())["name"]
    return profile


@app.get("/v1/me")
async def me(p: P) -> dict:
    async with db.tenant_tx(p.tenant_id) as cur:
        profile = await service.get_profile(cur, p.tenant_id, p.user_id, p.role)
    return await _with_tenant_name(profile)


@app.patch("/v1/me")
async def update_me(body: ProfileIn, p: P) -> dict:
    changes = body.model_dump(exclude_none=True)
    if "display_name" in changes:
        changes["display_name"] = changes["display_name"].strip()
    async with db.tenant_tx(p.tenant_id) as cur:
        profile = await service.update_profile(cur, p.tenant_id, p.user_id, p.role, changes)
    return await _with_tenant_name(profile)


class IncidentIn(BaseModel):
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9-]{1,64}$")
    device_id: str
    alert_ids: list[str]
    produced_by: str
    incident: dict
    proposal: dict


@app.post("/internal/incidents", dependencies=[Depends(require_service)])
async def internal_incident(body: IncidentIn) -> dict:
    try:
        async with db.tenant_tx(body.tenant_id) as cur:
            return await service.upsert_incident(cur, body.model_dump())
    except (ValueError, KeyError) as e:
        raise HTTPException(422, str(e)) from None
