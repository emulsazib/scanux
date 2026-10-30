"""Fakes: an in-memory graph mirroring what ingest/writers would store for the
office-cred-theft scenario, and a scripted LLM."""

from __future__ import annotations

import json

import pytest

from scanu_agents.entity import entity_id, file_id, proc_id
from scanu_agents.graphdb import merge, proc_node

T, D = "t-1", "dev-1"
UPD = r"C:\Users\<u:1a2b3c4d>\AppData\Local\Temp\upd.exe"
P = {
    "explorer": dict(pid=1000, start_ms=1, name="explorer.exe", image=r"C:\Windows\explorer.exe"),
    "word": dict(pid=2000, start_ms=2, name="WINWORD.EXE", image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    "ps": dict(pid=3000, start_ms=3, name="powershell.exe", image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
               cmdline="powershell -nop -w hidden -EncodedCommand ..."),
    "upd": dict(pid=4000, start_ms=4, name="upd.exe", image=UPD),
}
for v in P.values():
    v["id"] = proc_id(T, D, v["pid"], v["start_ms"])
SPAWN = [("explorer", "word"), ("word", "ps"), ("ps", "upd")]
C2_IP = entity_id("sock", T, "", "203.0.113.66:*")
C2_DNS = entity_id("dns", T, "", "xjw3kq9zr7vtp2.com")
LOGIN = file_id(T, D, r"C:\Users\<u:1a2b3c4d>\AppData\Local\Google\Chrome\User Data\Default\Login Data")


class FakeGraph:
    def __init__(self):
        self.calls = []

    async def process_tree(self, tenant, pid, depth):
        self.calls.append(("tree", tenant, pid))
        assert tenant == T
        if pid not in {v["id"] for v in P.values()}:
            return {"nodes": [], "edges": []}
        return {"nodes": [proc_node(v) for v in P.values()],
                "edges": [{"src": P[a]["id"], "dst": P[b]["id"], "type": "SPAWNED"} for a, b in SPAWN]}

    async def network_peers(self, tenant, pid):
        if pid == P["upd"]["id"]:
            return {"nodes": [{"id": C2_IP, "kind": "endpoint", "ip": "203.0.113.66"}],
                    "edges": [{"src": pid, "dst": C2_IP, "type": "CONNECTED", "count": 10, "mean_interval_s": 60.0, "jitter_cv": 0.004}]}
        if pid == P["ps"]["id"]:
            return {"nodes": [{"id": C2_DNS, "kind": "domain", "name": "xjw3kq9zr7vtp2.com"}],
                    "edges": [{"src": pid, "dst": C2_DNS, "type": "RESOLVED", "count": 1}]}
        return {"nodes": [], "edges": []}

    async def file_ops(self, tenant, pid, limit=50):
        if pid == P["upd"]["id"]:
            return {"nodes": [{"id": LOGIN, "kind": "file", "path": "...Login Data", "name": "Login Data"}],
                    "edges": [{"src": pid, "dst": LOGIN, "type": "READ", "count": 1}]}
        if pid == P["ps"]["id"]:
            f = file_id(T, D, UPD)
            return {"nodes": [{"id": f, "kind": "file", "path": UPD, "name": "upd.exe"}],
                    "edges": [{"src": pid, "dst": f, "type": "CREATED", "count": 1}]}
        return {"nodes": [], "edges": []}

    async def file_lineage(self, tenant, fid):
        return {"nodes": [], "edges": []}


def alert(kind, proc, severity="high", tier1="none", **extra):
    reason = {"kind": "heuristic", "name": kind, "score": 0.9, "detail": "x"} if kind not in ("ml", "canary") else {"kind": kind, "score": 0.999}
    return {
        "alert_id": f"alr_{kind}", "tenant_id": T, "device_id": D, "severity": severity, "confidence": 0.9,
        "tier1": tier1, "reason": reason, "event_ids": [],
        "process": {"pid": P[proc]["pid"], "start_time_unix_ms": P[proc]["start_ms"], "image_path": P[proc]["image"], "sha256": ""},
        "file_path": extra.get("file_path", ""), "file_sha256": extra.get("file_sha256", ""),
    }


@pytest.fixture
def cred_theft_alerts():
    return [
        alert("script_download_exec", "ps"),
        alert("dns_dga", "ps", severity="medium"),
        alert("ml", "upd", file_path=UPD, file_sha256="ab" * 32),
        alert("credential_store_access", "upd"),
        alert("beacon", "upd"),
    ]


class ScriptedLLM:
    """Plays back a list of (tool_name, args) per tool_loop call, records prompts."""

    def __init__(self, scripts: list[list[tuple[str, dict | str]]]):
        self.scripts = scripts
        self.prompts: list[str] = []
        self.outputs: list[str] = []

    def available(self):
        return True

    async def tool_loop(self, *, tier, task, data, tools, handler, max_turns=6):
        self.prompts.append(data)
        for name, args in self.scripts.pop(0) if self.scripts else []:
            out, done = await handler(name, args if isinstance(args, str) else json.dumps(args))
            self.outputs.append(out)
            if done:
                return True
        return False

    async def structured(self, **_):
        return {"keep": True, "category": "other", "rationale": "x"}
