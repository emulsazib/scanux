"""Loads schemas/tools/*.json and validates every model-issued call.

Two layers, both in code: (1) JSON Schema validation with the same schema the
provider enforced in strict mode, plus length limits strict mode can't
express; (2) an entity guard: every *_entity_id must already be in the
incident subgraph for this tenant.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

TOOLS_DIR = Path(os.getenv("SCANU_TOOLS_DIR", Path(__file__).resolve().parents[3] / "schemas" / "tools"))

MAX_LEN = {"explanation": 1200, "narrative": 2000, "title": 160, "rationale": 600}


class ToolViolation(Exception):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    spec: dict
    validator: Draft202012Validator


def _load() -> dict[str, Tool]:
    out = {}
    for f in sorted(TOOLS_DIR.glob("*.json")):
        spec = json.loads(f.read_text())
        schema = spec.get("parameters") or spec.get("schema")
        out[spec["name"]] = Tool(spec["name"], spec, Draft202012Validator(schema))
    return out


TOOLS = _load()


def openai_tools(names: list[str]) -> list[dict]:
    return [TOOLS[n].spec for n in names]


def response_format(name: str) -> dict:
    s = TOOLS[name].spec
    return {"type": "json_schema", "name": s["name"], "schema": s["schema"], "strict": True}


def _entity_ids(obj) -> list[str]:
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            if k.endswith("entity_id") and isinstance(v, str):
                out.append(v)
            elif k.endswith("entity_ids") and isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
            else:
                out += _entity_ids(v)
        return out
    if isinstance(obj, list):
        return [x for v in obj for x in _entity_ids(v)]
    return []


def validate_call(name: str, raw_args: str | dict, allowed: set[str], known_entities: set[str]) -> dict:
    if name not in allowed:
        raise ToolViolation(f"tool {name!r} is not permitted in this step")
    tool = TOOLS.get(name)
    if tool is None:
        raise ToolViolation(f"unknown tool {name!r}")
    try:
        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    except json.JSONDecodeError as e:
        raise ToolViolation(f"arguments are not JSON: {e}") from None
    errors = sorted(tool.validator.iter_errors(args), key=lambda e: e.path)
    if errors:
        raise ToolViolation("; ".join(e.message for e in errors[:3]))
    for field, limit in MAX_LEN.items():
        if isinstance(args.get(field), str) and len(args[field]) > limit:
            raise ToolViolation(f"{field} exceeds {limit} characters")
    unknown = [e for e in _entity_ids(args) if e not in known_entities]
    if unknown:
        raise ToolViolation(f"entity ids not in incident graph: {unknown[:3]}")
    return args
