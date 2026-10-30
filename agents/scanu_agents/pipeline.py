"""Perception → Correlation → Remediation as a LangGraph state machine.

Every step has a deterministic implementation; the LLM (when configured)
improves correlation and explanations but is never required for protection
and can never act outside the validated tool schemas.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TypedDict

from langgraph.graph import END, StateGraph

from . import redact
from .entity import file_id, incident_id, proc_id
from .graphdb import GraphStore, is_system_root, merge
from .llm import LLM
from .tools.registry import ToolViolation, openai_tools, response_format, validate_call

log = logging.getLogger("scanu.pipeline")

SEV_RANK = {"unspecified": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TECHNIQUES = {
    "script_download_exec": ["T1059.001", "T1105"],
    "dns_dga": ["T1568.002"],
    "dns_tunnel": ["T1071.004"],
    "beacon": ["T1071.001"],
    "credential_store_access": ["T1555.003"],
    "ml": ["T1204.002"],
    "bloom": ["T1204.002"],
    "canary": ["T1486"],
    "mass_modify": ["T1486"],
}
TITLE_PRIORITY = [
    ("canary", "Ransomware behaviour by {p}"),
    ("mass_modify", "Ransomware behaviour by {p}"),
    ("credential_store_access", "Credential theft via {p}"),
    ("beacon", "Command-and-control activity from {p}"),
    ("dns_tunnel", "DNS tunneling from {p}"),
    ("script_download_exec", "Malicious script execution from {p}"),
    ("dns_dga", "Suspicious domain lookups from {p}"),
    ("bloom", "Known malware {p}"),
    ("ml", "Suspicious executable {p}"),
]


class PipelineState(TypedDict, total=False):
    tenant_id: str
    device_id: str
    alerts: list[dict]
    keep: bool
    triage: dict
    seeds: list[str]
    root_id: str
    subgraph: dict
    incident: dict
    proposal: dict
    produced_by: str
    violations: list[str]


def kind_of(a: dict) -> str:
    return a["reason"].get("name") or a["reason"]["kind"]


def _name(n: dict | None) -> str:
    if not n:
        return "an unknown process"
    return n.get("name") or (n.get("image") or n.get("path") or n["id"]).replace("\\", "/").rsplit("/", 1)[-1]


class Pipeline:
    def __init__(self, graph: GraphStore, llm: LLM, graph_wait_s: float = 1.0, graph_retries: int = 8):
        self.g = graph
        self.llm = llm
        self.graph_wait_s = graph_wait_s
        self.graph_retries = graph_retries
        sg = StateGraph(PipelineState)
        sg.add_node("perception", self.perception)
        sg.add_node("correlation", self.correlation)
        sg.add_node("remediation", self.remediation)
        sg.set_entry_point("perception")
        sg.add_conditional_edges("perception", lambda s: "correlation" if s["keep"] else END)
        sg.add_edge("correlation", "remediation")
        sg.add_edge("remediation", END)
        self.app = sg.compile()

    async def run(self, tenant_id: str, device_id: str, alerts: list[dict]) -> PipelineState:
        return await self.app.ainvoke({"tenant_id": tenant_id, "device_id": device_id, "alerts": alerts, "violations": []})

    # ------------------------------------------------------------ perception
    async def perception(self, s: PipelineState) -> dict:
        t, d = s["tenant_id"], s["device_id"]
        for a in s["alerts"]:
            p = a.get("process") or {}
            a["_proc_entity_id"] = proc_id(t, d, p.get("pid", 0), p.get("start_time_unix_ms", 0)) if p else None
        kinds = {kind_of(a) for a in s["alerts"]}
        decisive = any(SEV_RANK.get(a["severity"], 0) >= 3 or a["tier1"] != "none" for a in s["alerts"]) or len(kinds) >= 2
        if decisive:
            return {"keep": True, "triage": {"by": "rules", "kinds": sorted(kinds)}}
        if self.llm.available():
            res = await self.llm.structured(
                tier="fast",
                task="Decide whether these endpoint alerts need investigation (keep=true) or are benign noise.",
                data=redact.for_prompt(s["alerts"], {"nodes": [], "edges": []}),
                fmt=response_format("triage_result"),
            )
            try:
                res = validate_call("triage_result", res or {}, {"triage_result"}, set())
                return {"keep": bool(res["keep"]), "triage": {"by": "llm", **res}}
            except ToolViolation as e:
                log.warning("triage output rejected: %s", e)
        return {"keep": False, "triage": {"by": "rules", "reason": "single low/medium signal"}}

    # ----------------------------------------------------------- correlation
    async def _neighbourhood(self, t: str, seeds: list[str]) -> dict:
        sub: dict = {"nodes": [], "edges": []}
        for attempt in range(self.graph_retries):
            sub = {"nodes": [], "edges": []}
            for sid in seeds:
                merge(sub, await self.g.process_tree(t, sid, 4))
                merge(sub, await self.g.network_peers(t, sid))
                merge(sub, await self.g.file_ops(t, sid, 25))
            if all(any(n["id"] == sid for n in sub["nodes"]) for sid in seeds):
                break
            await asyncio.sleep(self.graph_wait_s)  # writers may still be catching up
        return sub

    def _enrich(self, s: PipelineState, sub: dict) -> None:
        t, d = s["tenant_id"], s["device_id"]
        by_id = {n["id"]: n for n in sub["nodes"]}
        for a in s["alerts"]:
            pid_id = a.get("_proc_entity_id")
            if pid_id:
                n = by_id.get(pid_id)
                if n is None:
                    p = a["process"]
                    n = {"id": pid_id, "kind": "process", "pid": p["pid"], "start_ms": p["start_time_unix_ms"],
                         "image": p.get("image_path", ""), "name": _name({"image": p.get("image_path", ""), "id": pid_id})}
                    sub["nodes"].append(n)
                    by_id[pid_id] = n
                n.setdefault("alerts", [])
                if kind_of(a) not in n["alerts"]:
                    n["alerts"].append(kind_of(a))
            if a.get("file_path") and a.get("file_sha256"):
                fid = file_id(t, d, a["file_path"])
                f = by_id.get(fid)
                if f is None:
                    f = {"id": fid, "kind": "file", "path": a["file_path"], "name": _name({"path": a["file_path"], "id": fid})}
                    sub["nodes"].append(f)
                    by_id[fid] = f
                f["sha256"] = a["file_sha256"]
                if pid_id is None:  # file at rest (scan finding)
                    f.setdefault("alerts", [])
                    if kind_of(a) not in f["alerts"]:
                        f["alerts"].append(kind_of(a))
                    f["found_by_scan"] = bool(a.get("scan_id"))
                proc_n = by_id.get(pid_id or "")
                if proc_n is not None and proc_n.get("image", "").lower() == a["file_path"].lower():
                    if not proc_n.get("sha256"):
                        proc_n["sha256"] = a["file_sha256"]
                    merge(sub, {"edges": [{"src": proc_n["id"], "dst": fid, "type": "IMAGE"}]})

    @staticmethod
    def _root(sub: dict, seeds: list[str], alerts: list[dict] | None = None) -> str:
        if not seeds:  # scan findings only: anchor on the most severe flagged file (known-bad first)
            flagged = [n for n in sub["nodes"] if n.get("kind") == "file" and n.get("alerts")]
            return min(flagged, key=lambda n: (0 if "bloom" in n["alerts"] else 1, n["id"]))["id"]
        parents = {e["dst"]: e["src"] for e in sub["edges"] if e["type"] == "SPAWNED"}
        by_id = {n["id"]: n for n in sub["nodes"]}
        procs = sorted((by_id[s] for s in seeds if s in by_id), key=lambda n: n.get("start_ms") or 0)
        cur = procs[0]["id"] if procs else seeds[0]
        while cur in parents and not is_system_root(by_id.get(parents[cur], {})):
            cur = parents[cur]
        return cur

    def _deterministic_incident(self, s: PipelineState, sub: dict, root: str) -> dict:
        by_id = {n["id"]: n for n in sub["nodes"]}
        kinds = [kind_of(a) for a in s["alerts"]]
        sev = max(s["alerts"], key=lambda a: SEV_RANK.get(a["severity"], 0))["severity"]
        if any(a["tier1"] != "none" for a in s["alerts"]):
            sev = "critical"
        sev = sev if sev in ("low", "medium", "high", "critical") else "medium"
        flagged_files = [n for n in sub["nodes"] if n.get("kind") == "file" and n.get("alerts")]
        if all(a.get("scan_id") for a in s["alerts"]) and flagged_files:
            more = f" (+{len(flagged_files) - 1} more)" if len(flagged_files) > 1 else ""
            label = "Known malware found on disk" if "bloom" in kinds else "Suspicious file found by scan"
            title = f"{label}: {_name(by_id.get(root))}{more}"
        else:
            title = next((tpl.format(p=_name(by_id.get(root))) for k, tpl in TITLE_PRIORITY if k in kinds), "Suspicious activity")
        facts = []
        for a in s["alerts"]:
            if a.get("scan_id") and not a.get("_proc_entity_id"):
                fname = _name({"path": a.get("file_path", ""), "id": ""})
                r = a["reason"]
                facts.append(
                    f"a scan found {fname}, which matches a known-malware fingerprint" if r["kind"] == "bloom"
                    else f"a scan found {fname}, which the on-device model rates as likely malicious (score {r.get('score', 0):.2f})"
                )
                continue
            who = _name(by_id.get(a.get("_proc_entity_id") or ""))
            k, r = kind_of(a), a["reason"]
            facts.append({
                "script_download_exec": f"{who} ran a script that downloads and runs code from the internet",
                "dns_dga": f"{who} looked up a random-looking domain name, a common sign of malware contacting its operator",
                "dns_tunnel": f"{who} sent unusually long encoded DNS queries, which can hide stolen data",
                "ml": f"the on-device model rated {_name({'path': a.get('file_path', ''), 'id': ''}) or who} as likely malicious (score {r.get('score', 0):.2f})",
                "bloom": f"{who} matches a known-malware fingerprint",
                "credential_store_access": f"{who} opened the browser's saved-password database, which only the browser itself should read",
                "beacon": f"{who} contacted the same server at regular intervals ({r.get('detail', '')}), typical of remote-control malware",
                "canary": f"{who} tried to change a hidden decoy file, which is how ransomware behaves; Scanu paused it in {r.get('frozen_us', 0)} µs",
                "mass_modify": f"{who} changed many files within seconds",
            }.get(k, f"{who} triggered {k}"))
        chain = [n for n in sub["nodes"] if n.get("kind") == "process"]
        chain.sort(key=lambda n: n.get("start_ms") or 0)
        if chain:
            narrative = (
                f"Starting from {_name(by_id.get(root))}, "
                + "; ".join(dict.fromkeys(facts))
                + f". Processes involved: {', '.join(dict.fromkeys(_name(n) for n in chain))}."
            )
        else:
            narrative = ("; ".join(dict.fromkeys(facts)).capitalize()
                         + ". The file(s) were found at rest and have not been seen running on this device.")
        narrative = narrative[:2000]
        techniques = sorted({t for k in kinds for t in TECHNIQUES.get(k, [])})
        return {"title": title[:160], "severity": sev, "narrative": narrative, "member_entity_ids": [n["id"] for n in sub["nodes"]][:64], "attack_techniques": techniques}

    async def correlation(self, s: PipelineState) -> dict:
        t, d = s["tenant_id"], s["device_id"]
        seeds = list(dict.fromkeys(a["_proc_entity_id"] for a in s["alerts"] if a.get("_proc_entity_id")))
        sub = await self._neighbourhood(t, seeds)
        self._enrich(s, sub)
        root = self._root(sub, seeds, s["alerts"])
        produced_by = "rules"
        violations = list(s.get("violations", []))
        result: dict | None = None

        if self.llm.available():
            known = {n["id"] for n in sub["nodes"]}
            allowed = {"get_process_tree", "get_file_lineage", "get_network_peers", "submit_incident"}

            async def handler(name: str, raw: str) -> tuple[str, bool]:
                nonlocal result
                try:
                    args = validate_call(name, raw, allowed, known)
                except ToolViolation as e:
                    violations.append(f"correlation:{name}:{e}")
                    if len(violations) >= 3:
                        return json.dumps({"error": "too many invalid calls"}), True
                    return json.dumps({"error": str(e)}), False
                if name == "submit_incident":
                    result = args
                    return "ok", True
                more = await {
                    "get_process_tree": lambda: self.g.process_tree(t, args.get("process_entity_id", ""), args.get("depth", 2)),
                    "get_file_lineage": lambda: self.g.file_lineage(t, args.get("file_entity_id", "")),
                    "get_network_peers": lambda: self.g.network_peers(t, args.get("process_entity_id", "")),
                }[name]()
                merge(sub, more)
                known.update(n["id"] for n in more["nodes"])
                return json.dumps(redact.clean(more)), False

            await self.llm.tool_loop(
                tier="reasoning",
                task=("Correlate these alerts into one incident. Use the read-only graph functions if you need more context, "
                      "then call submit_incident with a plain-language narrative for a non-expert home user."),
                data=redact.for_prompt(s["alerts"], sub),
                tools=openai_tools(sorted(allowed)),
                handler=handler,
            )
            if result:
                produced_by = "llm"

        incident = result or self._deterministic_incident(s, sub, root)
        incident["incident_id"] = incident_id(t, d, root)
        incident["graph"] = sub
        return {"seeds": seeds, "root_id": root, "subgraph": sub, "incident": incident, "produced_by": produced_by, "violations": violations}

    # ----------------------------------------------------------- remediation
    def _candidates(self, s: PipelineState) -> tuple[list[dict], list[dict]]:
        sub = s["subgraph"]
        by_id = {n["id"]: n for n in sub["nodes"]}
        children: dict[str, list[str]] = {}
        for e in sub["edges"]:
            if e["type"] == "SPAWNED":
                children.setdefault(e["src"], []).append(e["dst"])
        procs, stack = [], list(s["seeds"])
        while stack:
            pid = stack.pop()
            n = by_id.get(pid)
            if n and n.get("kind") == "process" and n not in procs and not is_system_root(n):
                procs.append(n)
                stack += children.get(pid, [])
        proc_ids = {p["id"] for p in procs}
        files = [
            by_id[e["dst"]]
            for e in sub["edges"]
            if e["src"] in proc_ids and e["type"] in ("IMAGE", "CREATED") and by_id.get(e["dst"], {}).get("sha256")
        ]
        # Files flagged at rest (scan findings) are quarantine targets too.
        files += [n for n in sub["nodes"] if n.get("kind") == "file" and n.get("alerts") and n.get("sha256")]
        return procs, list({f["id"]: f for f in files}.values())

    async def remediation(self, s: PipelineState) -> dict:
        inc = s["incident"]
        procs, files = self._candidates(s)
        violations = list(s.get("violations", []))
        proposal: dict | None = None

        if self.llm.available():
            known = {n["id"] for n in s["subgraph"]["nodes"]} | {inc["incident_id"]}

            async def handler(name: str, raw: str) -> tuple[str, bool]:
                nonlocal proposal
                try:
                    args = validate_call(name, raw, {"propose_playbook"}, known)
                    if args["incident_id"] != inc["incident_id"]:
                        raise ToolViolation("incident_id mismatch")
                except ToolViolation as e:
                    violations.append(f"remediation:{name}:{e}")
                    if len(violations) >= 3:
                        return json.dumps({"error": "too many invalid calls"}), True
                    return json.dumps({"error": str(e)}), False
                proposal = args
                return "ok", True

            await self.llm.tool_loop(
                tier="reasoning",
                task=(f"Incident {inc['incident_id']}: {inc['title']}. Propose a containment playbook for human approval with "
                      "propose_playbook. Prefer the least destructive option that stops the threat. Explain in plain language "
                      "why, what each step does, and that file quarantine can be undone."),
                data=redact.for_prompt(s["alerts"], s["subgraph"]),
                tools=openai_tools(["propose_playbook"]),
                handler=handler,
            )

        if proposal is None:
            choice = "terminate_and_quarantine" if inc["severity"] in ("high", "critical") else "isolate_network_only"
            steps = [{"tool": "terminate", "target_entity_id": p["id"]} for p in procs]
            steps += [{"tool": "quarantine", "target_entity_id": f["id"]} for f in files]
            names = ", ".join(_name(p) for p in procs) or "the process"
            frozen = any(a["tier1"] != "none" for a in s["alerts"])
            vault_txt = f"move {len(files)} file(s) into the encrypted vault (you can restore them later)"
            action_txt = {
                "terminate_and_quarantine": f"stop {names} and {vault_txt}" if procs else vault_txt,
                "isolate_network_only": f"cut {names} off the network while letting it keep running",
            }[choice]
            explanation = (
                f"What happened: {inc['narrative']} "
                + ("What Scanu already did: the process was paused and blocked from the network on your device. " if frozen else "")
                + f"Recommended: {action_txt}. Nothing happens until you approve."
            )
            proposal = {"incident_id": inc["incident_id"], "recommended_choice": choice, "steps": steps[:8], "explanation": explanation[:1200]}
        return {"proposal": proposal, "violations": violations}
