"""Prepares untrusted telemetry for an LLM prompt.

The sensor already pseudonymizes users and profile paths. Here we (1) drop
fields the model doesn't need, (2) cap lengths, (3) strip control characters
and anything that could close our data delimiter, and (4) alias the device ID.
"""

from __future__ import annotations

import json
import re
from typing import Any

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DELIM = re.compile(r"</?\s*untrusted_data\s*>", re.IGNORECASE)
KEEP_NODE = {"id", "kind", "name", "image", "path", "cmdline", "pid", "label", "ip", "port", "sha256"}


def clean_str(s: str, limit: int = 300) -> str:
    s = _CTRL.sub("", s)
    s = _DELIM.sub("[delimiter-removed]", s)
    return s if len(s) <= limit else s[:limit] + "…"


def clean(obj: Any, limit: int = 300) -> Any:
    if isinstance(obj, str):
        return clean_str(obj, limit)
    if isinstance(obj, list):
        return [clean(x, limit) for x in obj[:64]]
    if isinstance(obj, dict):
        return {k: clean(v, limit) for k, v in obj.items()}
    return obj


def for_prompt(alerts: list[dict], subgraph: dict, device_alias: str = "device-1") -> str:
    nodes = [{k: v for k, v in n.items() if k in KEEP_NODE} for n in subgraph.get("nodes", [])]
    data = {
        "device": device_alias,
        "alerts": [
            {
                "kind": a["reason"].get("name") or a["reason"]["kind"],
                "severity": a["severity"],
                "confidence": a["confidence"],
                "tier1": a["tier1"],
                "process_entity_id": a.get("_proc_entity_id"),
                "detail": a["reason"].get("detail", ""),
            }
            for a in alerts
        ],
        "graph": {"nodes": nodes, "edges": subgraph.get("edges", [])[:200]},
    }
    return "<untrusted_data>\n" + json.dumps(clean(data), ensure_ascii=False) + "\n</untrusted_data>"
