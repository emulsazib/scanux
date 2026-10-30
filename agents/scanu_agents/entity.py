"""Entity IDs, identical to ingest/writers (schemas/testvectors/entity_ids.json)."""

import hashlib


def entity_id(kind: str, tenant: str, device: str, natural: str) -> str:
    return f"{kind}_" + hashlib.sha256(f"{tenant}|{device}|{natural}".encode()).hexdigest()[:32]


def proc_id(tenant: str, device: str, pid: int, start_ms: int) -> str:
    return entity_id("proc", tenant, device, f"{pid}:{start_ms}")


def file_id(tenant: str, device: str, path: str) -> str:
    return entity_id("file", tenant, device, path.lower())


def incident_id(tenant: str, device: str, root_entity: str) -> str:
    return "inc_" + hashlib.sha256(f"{tenant}|{device}|{root_entity}".encode()).hexdigest()[:32]
