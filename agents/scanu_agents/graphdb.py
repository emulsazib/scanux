"""Read-only graph queries. Parameterized Cypher only; `tenant_id` is injected
here and never taken from the model. The model never writes Cypher."""

from __future__ import annotations

import os
import statistics
from typing import Protocol

import httpx

_SYSTEM_ROOTS = {"explorer.exe", "services.exe", "wininit.exe", "userinit.exe", "svchost.exe", "systemd", "launchd", "init"}


class GraphStore(Protocol):
    async def process_tree(self, tenant: str, proc_id: str, depth: int) -> dict: ...
    async def file_lineage(self, tenant: str, file_id: str) -> dict: ...
    async def network_peers(self, tenant: str, proc_id: str) -> dict: ...
    async def file_ops(self, tenant: str, proc_id: str, limit: int = 50) -> dict: ...


def proc_node(p: dict) -> dict:
    return {
        "id": p["id"], "kind": "process", "pid": p.get("pid"), "start_ms": p.get("start_ms"),
        "image": p.get("image", ""), "name": p.get("name") or (p.get("image", "").replace("\\", "/").rsplit("/", 1)[-1]),
        "cmdline": p.get("cmdline", ""), "sha256": p.get("sha256", ""),
    }


def beacon_stats(times: list[int]) -> dict:
    if len(times) < 3:
        return {}
    iv = [b - a for a, b in zip(times, times[1:])]
    mean = statistics.fmean(iv)
    cv = statistics.pstdev(iv) / mean if mean else 0.0
    return {"mean_interval_s": round(mean / 1000, 1), "jitter_cv": round(cv, 3)}


class Neo4jHttp:
    def __init__(self, url: str | None = None, user: str | None = None, password: str | None = None):
        self.url = (url or os.getenv("SCANU_NEO4J_URL", "http://127.0.0.1:7474")) + "/db/neo4j/tx/commit"
        self.auth = (user or os.getenv("SCANU_NEO4J_USER", "neo4j"), password or os.getenv("SCANU_NEO4J_PASSWORD", "scanu-dev-pass"))

    async def _q(self, statement: str, **params) -> list[list]:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(self.url, auth=self.auth, json={"statements": [{"statement": statement, "parameters": params}]})
        body = r.json()
        if body.get("errors"):
            raise RuntimeError(body["errors"])
        return [row["row"] for row in body["results"][0]["data"]]

    async def process_tree(self, tenant: str, proc_id: str, depth: int) -> dict:
        depth = max(1, min(4, int(depth)))  # interpolated only as a validated int
        rows = await self._q(
            f"""MATCH (p:Process {{id: $id, tenant_id: $tenant}})
                OPTIONAL MATCH (a:Process)-[:SPAWNED*1..{depth}]->(p) WHERE a.tenant_id = $tenant
                OPTIONAL MATCH (p)-[:SPAWNED*1..{depth}]->(d:Process) WHERE d.tenant_id = $tenant
                WITH p, collect(DISTINCT a) + collect(DISTINCT d) + [p] AS ps
                UNWIND ps AS x
                OPTIONAL MATCH (x)-[:SPAWNED]->(c:Process) WHERE c IN ps
                RETURN x {{.*}}, collect(c.id)""",
            id=proc_id, tenant=tenant,
        )
        nodes = [proc_node(x) for x, _ in rows]
        edges = [{"src": x["id"], "dst": c, "type": "SPAWNED"} for x, cs in rows for c in cs]
        return {"nodes": nodes, "edges": edges}

    async def file_lineage(self, tenant: str, file_id: str) -> dict:
        rows = await self._q(
            """MATCH (f:File {id: $id, tenant_id: $tenant})
               OPTIONAL MATCH (p:Process)-[e:FILE_OP]->(f) WHERE p.tenant_id = $tenant
               OPTIONAL MATCH (r:Process)-[:IMAGE]->(f) WHERE r.tenant_id = $tenant
               RETURN f {.*}, collect(DISTINCT [p {.*}, e.op, e.count]), collect(DISTINCT r {.*})""",
            id=file_id, tenant=tenant,
        )
        if not rows:
            return {"nodes": [], "edges": []}
        f, ops, runs = rows[0]
        nodes = [{"id": f["id"], "kind": "file", "path": f.get("path", ""), "name": f.get("name", ""), "sha256": f.get("sha256", "")}]
        edges = []
        for p, op, count in ops:
            if p:
                nodes.append(proc_node(p))
                edges.append({"src": p["id"], "dst": f["id"], "type": op, "count": count})
        for r in runs:
            if r:
                nodes.append(proc_node(r))
                edges.append({"src": r["id"], "dst": f["id"], "type": "IMAGE"})
        return {"nodes": nodes, "edges": edges}

    async def network_peers(self, tenant: str, proc_id: str) -> dict:
        rows = await self._q(
            """MATCH (p:Process {id: $id, tenant_id: $tenant})
               OPTIONAL MATCH (p)-[c:CONNECTED]->(e:Endpoint) WHERE e.tenant_id = $tenant
               OPTIONAL MATCH (p)-[r:RESOLVED]->(d:Domain) WHERE d.tenant_id = $tenant
               RETURN collect(DISTINCT [e {.*}, c.port, c.count, c.bytes_out, c.bytes_in, c.times]),
                      collect(DISTINCT [d {.*}, r.count])""",
            id=proc_id, tenant=tenant,
        )
        if not rows:
            return {"nodes": [], "edges": []}
        conns, dnss = rows[0]
        nodes, edges = [], []
        for e, port, count, bout, bin_, times in conns:
            if e:
                nodes.append({"id": e["id"], "kind": "endpoint", "ip": e.get("ip", ""), "label": e.get("ip", "")})
                edges.append({"src": proc_id, "dst": e["id"], "type": "CONNECTED", "port": port, "count": count,
                              "bytes_out": bout, "bytes_in": bin_, **beacon_stats(times or [])})
        for d, count in dnss:
            if d:
                nodes.append({"id": d["id"], "kind": "domain", "name": d.get("name", ""), "label": d.get("name", "")})
                edges.append({"src": proc_id, "dst": d["id"], "type": "RESOLVED", "count": count})
        return {"nodes": nodes, "edges": edges}

    async def file_ops(self, tenant: str, proc_id: str, limit: int = 50) -> dict:
        rows = await self._q(
            """MATCH (p:Process {id: $id, tenant_id: $tenant})-[e:FILE_OP]->(f:File) WHERE f.tenant_id = $tenant
               RETURN f {.*}, e.op, e.count ORDER BY e.last_ms DESC LIMIT $limit""",
            id=proc_id, tenant=tenant, limit=limit,
        )
        nodes = [{"id": f["id"], "kind": "file", "path": f.get("path", ""), "name": f.get("name", ""), "sha256": f.get("sha256", "")} for f, _, _ in rows]
        edges = [{"src": proc_id, "dst": f["id"], "type": op, "count": n} for f, op, n in rows]
        return {"nodes": nodes, "edges": edges}


def merge(into: dict, more: dict) -> dict:
    seen = {n["id"]: n for n in into.setdefault("nodes", [])}
    for n in more.get("nodes", []):
        if n["id"] in seen:
            seen[n["id"]].update({k: v for k, v in n.items() if v not in (None, "")})
        else:
            into["nodes"].append(n)
            seen[n["id"]] = n
    keys = {(e["src"], e["dst"], e["type"]) for e in into.setdefault("edges", [])}
    for e in more.get("edges", []):
        if (e["src"], e["dst"], e["type"]) not in keys:
            into["edges"].append(e)
            keys.add((e["src"], e["dst"], e["type"]))
    return into


def is_system_root(node: dict) -> bool:
    return (node.get("name") or "").lower() in _SYSTEM_ROOTS
