"""End-to-end MVP loop against locally running services (make up + gateway/writers/api/agents).

    cd api && uv run python ../tests/e2e/run_e2e.py

1. sensor-sim replays office-cred-theft over mTLS and stays connected.
2. Agents correlate → API holds an incident + PROPOSED action.
3. We approve "terminate_and_quarantine" (human-in-the-loop).
4. API signs commands → gateway → sensor verifies + executes → VERIFIED.
5. Rollback restores the quarantined file → ROLLED_BACK.
6. A forged command (attacker key) is rejected by the sensor.
7. Ransomware scenario: Tier-1 freeze < 100 ms, incident created.
8. On-demand full scan finds dormant malware → incident → approve → quarantined.
9. Audit chain verifies; raw OCSF is queryable from ClickHouse.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
from aiokafka import AIOKafkaProducer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "api"))
from scanu_api.gen import alert_pb2, command_pb2  # noqa: E402

API = os.getenv("SCANU_API", "http://127.0.0.1:8000")
H = {"Authorization": "Bearer dev-owner-token"}
TENANT = "11111111-1111-4111-8111-111111111111"
DEVICE = "dev-sim-1"
SIM = ROOT / "target/debug/sensor-sim"


def step(msg: str) -> None:
    print(f"\n\033[1;32m▶ {msg}\033[0m", flush=True)


def wait(fn, timeout=60, every=1.0, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(every)
    raise TimeoutError(f"timed out waiting for {what}")


def sim(scenario: str, data: Path, linger: int) -> subprocess.Popen:
    return subprocess.Popen(
        [str(SIM), "--device", DEVICE, "--pki", str(ROOT / "deploy/pki/out"), "--data", str(data), "scenario", scenario, "--linger", str(linger)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "RUST_LOG": "warn,engine=info"},
    )


async def forge_command(device: str) -> None:
    attacker = Ed25519PrivateKey.generate()
    rc = command_pb2.RemediationCommand(command_id=f"cmd_forged_{uuid.uuid4().hex[:8]}", action_id="act_forged",
                                        device_id=device, nonce=42, approval_ref="dec_forged")
    rc.not_after.seconds = int(time.time()) + 120
    rc.terminate.CopyFrom(command_pb2.TerminateProcess(process=alert_pb2.ProcessRef(pid=3000, start_time_unix_ms=1)))
    body = rc.SerializeToString()
    key_id = (ROOT / "deploy/pki/out/cmd-signing.key_id").read_text().strip()  # claims the real key id
    sc = command_pb2.SignedCommand(command=body, ed25519_sig=attacker.sign(body), key_id=key_id)
    p = AIOKafkaProducer(bootstrap_servers=os.getenv("SCANU_KAFKA", "127.0.0.1:19092"))
    await p.start()
    try:
        await p.send_and_wait("scanu.commands", json.dumps({"tenant_id": TENANT, "device_id": device,
                              "signed_command_b64": base64.b64encode(sc.SerializeToString()).decode()}).encode())
    finally:
        await p.stop()


def main() -> int:
    c = httpx.Client(base_url=API, headers=H, timeout=10)
    data = ROOT / f".data/e2e/{int(time.time())}"
    before = {i["incident_id"] for i in c.get("/v1/incidents").json()}

    step("1. sensor-sim: office-cred-theft over mTLS")
    p = sim("office-cred-theft", data, linger=90)

    step("2. waiting for agents to correlate an incident")
    inc = wait(lambda: next((i for i in c.get("/v1/incidents").json() if i["incident_id"] not in before and i["action_state"] == "PROPOSED"), None),
               timeout=60, what="incident")
    detail = c.get(f"/v1/incidents/{inc['incident_id']}").json()
    action = detail["actions"][-1]
    print(f"  incident: {inc['title']} [{inc['severity']}] {inc['attack_techniques']}")
    print(f"  narrative: {detail['incident']['narrative'][:300]}…")
    print(f"  graph: {len(detail['incident']['graph']['nodes'])} nodes / {len(detail['incident']['graph']['edges'])} edges")
    print(f"  proposal ({action['recommended_choice']}): {[(s['tool'], s['target_entity_id'][:13]) for s in action['proposal']['steps']]}")

    step("3. human approves Terminate & Quarantine")
    r = c.post(f"/v1/actions/{action['action_id']}/decision", json={"choice": "terminate_and_quarantine", "channel": "web"}).json()
    print(f"  decision {r['decision_id']} → {r['state']}, {len(r['commands'])} signed command(s)")

    step("4. waiting for sensor execution + on-device verification")
    def state():
        a = next(a for a in c.get(f"/v1/incidents/{inc['incident_id']}").json()["actions"] if a["action_id"] == action["action_id"])
        return a["state"] if a["state"] in ("VERIFIED", "FAILED") else None
    final = wait(state, timeout=30, what="VERIFIED")
    cmds = c.get(f"/v1/incidents/{inc['incident_id']}").json()["commands"]
    for cmd in cmds:
        print(f"  {cmd['tool']:<11} {cmd['status']:<9} {cmd['reason'] or ''} {cmd['vault_id'] or ''}")
    assert final == "VERIFIED", final

    step("5. rollback (restore quarantined file from the encrypted vault)")
    rb = c.post(f"/v1/actions/{action['action_id']}/rollback").json()
    print(f"  rollback decision {rb['decision_id']}, {len(rb['commands'])} command(s)")
    def rolled():
        a = next(a for a in c.get(f"/v1/incidents/{inc['incident_id']}").json()["actions"] if a["action_id"] == action["action_id"])
        return a["state"] == "ROLLED_BACK"
    wait(rolled, timeout=30, what="ROLLED_BACK")
    restored = data / "fs/C/Users/alice/AppData/Local/Temp/upd.exe"
    print(f"  ROLLED_BACK; file restored on device: {restored.exists()}")
    assert restored.exists()

    step("6. adversarial: forged command signed with an attacker key")
    asyncio.run(forge_command(DEVICE))
    time.sleep(3)

    p.terminate()
    out, _ = p.communicate(timeout=15)
    sim_lines = [line for line in out.splitlines() if any(k in line for k in ("COMMAND", "ALERT", "BAD_SIGNATURE", "rejected"))]
    print("  sensor output:\n    " + "\n    ".join(sim_lines[-8:]))
    assert any("BAD_SIGNATURE" in line for line in out.splitlines()), "forged command must be rejected"

    step("7. ransomware: Tier-1 freeze + incident")
    before2 = {i["incident_id"] for i in c.get("/v1/incidents").json()}
    p2 = sim("ransomware", ROOT / f".data/e2e/{int(time.time())}-r", linger=20)
    inc2 = wait(lambda: next((i for i in c.get("/v1/incidents").json() if i["incident_id"] not in before2), None), timeout=60, what="ransomware incident")
    d2 = c.get(f"/v1/incidents/{inc2['incident_id']}").json()
    canary = next(a for a in d2["alerts"] if a["kind"] == "canary")
    print(f"  {inc2['title']} [{inc2['severity']}] tier1={canary['tier1']} frozen_in={canary['payload']['reason']['frozen_us']}µs")
    assert canary["payload"]["reason"]["frozen_us"] < 100_000
    p2.terminate()
    p2.communicate(timeout=15)

    step("8. on-demand full system scan finds dormant malware")
    before3 = {i["incident_id"] for i in c.get("/v1/incidents").json()}
    data3 = ROOT / f".data/e2e/{int(time.time())}-d"
    p3 = sim("dormant", data3, linger=90)
    wait(lambda: any(d["device_id"] == DEVICE and d["online"] for d in c.get("/v1/devices").json()), timeout=20, what="device online")
    scan = c.post(f"/v1/devices/{DEVICE}/scans", json={"scope": "full"}).json()
    print(f"  requested {scan['scan_id']} ({scan['scope']}) → {scan['state']}")
    busy = c.post(f"/v1/devices/{DEVICE}/scans", json={"scope": "quick"})
    print(f"  second scan while busy → HTTP {busy.status_code}")
    assert busy.status_code == 409
    done = wait(lambda: next((x for x in c.get("/v1/scans", params={"device_id": DEVICE}).json()
                              if x["scan_id"] == scan["scan_id"] and x["state"] in ("completed", "failed", "cancelled")), None),
                timeout=30, what="scan completion")
    print(f"  {done['state']}: {done['files_seen']} files, {done['files_analyzed']} analyzed, {done['findings']} findings")
    assert done["state"] == "completed" and done["findings"] == 2
    inc3 = wait(lambda: next((i for i in c.get("/v1/incidents").json() if i["incident_id"] not in before3 and i["action_state"] == "PROPOSED"), None),
                timeout=60, what="scan incident")
    d3 = c.get(f"/v1/incidents/{inc3['incident_id']}").json()
    a3 = d3["actions"][-1]
    print(f"  {inc3['title']} [{inc3['severity']}] → proposal {[s['tool'] for s in a3['proposal']['steps']]}")
    c.post(f"/v1/actions/{a3['action_id']}/decision", json={"choice": "terminate_and_quarantine", "channel": "web"})
    def verified3():
        a = c.get(f"/v1/incidents/{inc3['incident_id']}").json()["actions"][-1]
        return a["state"] if a["state"] in ("VERIFIED", "FAILED") else None
    assert wait(verified3, timeout=30, what="scan remediation") == "VERIFIED"
    gone = [not (data3 / "fs" / rel).exists() for rel in ("C/Users/alice/Downloads/invoice_viewer.exe", "C/Users/alice/AppData/Roaming/Microsoft/updater.exe")]
    print(f"  VERIFIED; both files moved to the vault: {all(gone)}")
    assert all(gone)
    p3.terminate()
    p3.communicate(timeout=15)

    step("9. audit chain + raw telemetry")
    print(f"  audit: {c.get('/v1/audit/verify').json()}")
    ev = c.get("/v1/events", params={"device_id": DEVICE, "limit": 1000}).json()
    print(f"  ClickHouse OCSF events for {DEVICE}: {len(ev)} (classes {sorted({e['class_uid'] for e in ev})})")
    print("\n\033[1;32mE2E PASSED\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
