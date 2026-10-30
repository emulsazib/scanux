"""HITL Tier-3 lifecycle and the mapping from a human choice to sensor commands.

The LLM only ever chooses *targets* (graph entity IDs) and *recommends* a
choice. The human's choice decides which tools run, and this module (plain
code) builds the commands.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class State(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


TRANSITIONS: dict[State, frozenset[State]] = {
    State.PROPOSED: frozenset({State.APPROVED, State.REJECTED}),
    State.APPROVED: frozenset({State.EXECUTED, State.FAILED}),
    State.EXECUTED: frozenset({State.VERIFIED, State.FAILED}),
    State.VERIFIED: frozenset({State.ROLLED_BACK}),
    State.FAILED: frozenset({State.PROPOSED}),
    State.REJECTED: frozenset(),
    State.ROLLED_BACK: frozenset(),
}


class IllegalTransition(Exception):
    pass


def check_transition(current: str, target: str) -> None:
    cur, tgt = State(current), State(target)
    if tgt not in TRANSITIONS[cur]:
        raise IllegalTransition(f"{cur} -> {tgt} is not allowed")


class Choice(StrEnum):
    TERMINATE_AND_QUARANTINE = "terminate_and_quarantine"
    ISOLATE_NETWORK_ONLY = "isolate_network_only"
    ALLOW_AND_WHITELIST = "allow_and_whitelist"
    REJECT = "reject"


@dataclass(frozen=True)
class PlannedCommand:
    tool: str  # suspend | resume | terminate | net_block | net_unblock | quarantine | restore | allowlist
    args: dict


def _node(graph: dict, entity_id: str) -> dict | None:
    return next((n for n in graph.get("nodes", []) if n.get("id") == entity_id), None)


def _proc_ref(n: dict) -> dict:
    return {
        "pid": int(n["pid"]),
        "start_time_unix_ms": int(n["start_ms"]),
        "image_path": n.get("image", ""),
        "sha256": n.get("sha256", ""),
    }


def plan_commands(choice: Choice, proposal: dict, graph: dict) -> list[PlannedCommand]:
    """Builds the concrete command list. Targets come only from proposal steps
    whose entity IDs resolve to nodes in the incident graph."""
    procs: list[dict] = []
    files: list[dict] = []
    for step in proposal.get("steps", []):
        n = _node(graph, step["target_entity_id"])
        if n is None:
            continue
        if n.get("kind") == "process" and n.get("pid") is not None and n.get("start_ms") is not None:
            if n not in procs:
                procs.append(n)
        elif n.get("kind") == "file" and n.get("sha256"):
            if n not in files:
                files.append(n)

    out: list[PlannedCommand] = []
    if choice == Choice.TERMINATE_AND_QUARANTINE:
        out += [PlannedCommand("terminate", {"process": _proc_ref(p)}) for p in procs]
        out += [PlannedCommand("quarantine", {"path": f["path"], "sha256": f["sha256"]}) for f in files]
    elif choice == Choice.ISOLATE_NETWORK_ONLY:
        # Keep the process off the network, let it run (undo a Tier-1 suspend).
        out += [PlannedCommand("net_block", {"process": _proc_ref(p)}) for p in procs]
        out += [PlannedCommand("resume", {"process": _proc_ref(p)}) for p in procs]
    elif choice == Choice.ALLOW_AND_WHITELIST:
        hashes = {p["sha256"] for p in procs if p.get("sha256")} | {f["sha256"] for f in files}
        out += [PlannedCommand("allowlist", {"sha256": h}) for h in sorted(hashes)]
        out += [PlannedCommand("net_unblock", {"process": _proc_ref(p)}) for p in procs]
        out += [PlannedCommand("resume", {"process": _proc_ref(p)}) for p in procs]
    return out


INVERSE = {"quarantine": "restore", "net_block": "net_unblock", "suspend": "resume"}


def plan_rollback(executed: list[dict]) -> list[PlannedCommand]:
    """Inverse of executed commands. `terminate` cannot be undone (documented)."""
    out = []
    for c in executed:
        if c["tool"] == "quarantine" and c.get("vault_id"):
            out.append(PlannedCommand("restore", {"vault_id": c["vault_id"]}))
        elif c["tool"] in ("net_block", "suspend"):
            out.append(PlannedCommand(INVERSE[c["tool"]], c["args"]))
    return out
