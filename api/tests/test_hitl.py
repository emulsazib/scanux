import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scanu_api.audit import GENESIS, row_hash, verify_chain
from scanu_api.gen import command_pb2
from scanu_api.hitl import Choice, IllegalTransition, State, check_transition, plan_commands, plan_rollback
from scanu_api.service import validate_incident
from scanu_api.signer import CommandSigner

GRAPH = {
    "nodes": [
        {"id": "proc_" + "a" * 32, "kind": "process", "pid": 4000, "start_ms": 123, "image": "C:\\x\\upd.exe", "sha256": "ab" * 32},
        {"id": "file_" + "b" * 32, "kind": "file", "path": "C:\\x\\upd.exe", "sha256": "ab" * 32},
        {"id": "proc_" + "c" * 32, "kind": "process"},  # no pid/start: unresolvable
    ]
}
PROPOSAL = {
    "incident_id": "inc_" + "d" * 32,
    "recommended_choice": "terminate_and_quarantine",
    "steps": [
        {"tool": "terminate", "target_entity_id": "proc_" + "a" * 32},
        {"tool": "quarantine", "target_entity_id": "file_" + "b" * 32},
        {"tool": "terminate", "target_entity_id": "proc_" + "c" * 32},
        {"tool": "terminate", "target_entity_id": "proc_" + "e" * 32},  # not in graph
    ],
    "explanation": "x",
}


def test_transition_table():
    check_transition("PROPOSED", "APPROVED")
    check_transition("EXECUTED", "VERIFIED")
    check_transition("VERIFIED", "ROLLED_BACK")
    for cur, tgt in [("PROPOSED", "EXECUTED"), ("REJECTED", "APPROVED"), ("ROLLED_BACK", "VERIFIED"), ("APPROVED", "VERIFIED")]:
        with pytest.raises(IllegalTransition):
            check_transition(cur, tgt)


def test_choice_determines_tools_and_only_graph_targets_resolve():
    cmds = plan_commands(Choice.TERMINATE_AND_QUARANTINE, PROPOSAL, GRAPH)
    assert [c.tool for c in cmds] == ["terminate", "quarantine"]
    assert cmds[0].args["process"]["pid"] == 4000
    iso = plan_commands(Choice.ISOLATE_NETWORK_ONLY, PROPOSAL, GRAPH)
    assert [c.tool for c in iso] == ["net_block", "resume"]
    allow = plan_commands(Choice.ALLOW_AND_WHITELIST, PROPOSAL, GRAPH)
    assert [c.tool for c in allow] == ["allowlist", "net_unblock", "resume"]


def test_rollback_inverts_reversible_only():
    rb = plan_rollback([
        {"tool": "terminate", "args": {}, "vault_id": ""},
        {"tool": "quarantine", "args": {}, "vault_id": "vlt_1"},
        {"tool": "net_block", "args": {"process": {"pid": 1}}, "vault_id": ""},
    ])
    assert [(c.tool, c.args) for c in rb] == [("restore", {"vault_id": "vlt_1"}), ("net_unblock", {"process": {"pid": 1}})]


def test_signer_produces_verifiable_protobuf():
    key = Ed25519PrivateKey.generate()
    s = CommandSigner(key, "cmd-test", ttl_s=60)
    cmd = plan_commands(Choice.TERMINATE_AND_QUARANTINE, PROPOSAL, GRAPH)[0]
    signed = s.sign(cmd, device_id="dev-1", action_id="act_1", approval_ref="dec_1")
    sc = command_pb2.SignedCommand.FromString(base64.b64decode(signed.envelope_b64))
    key.public_key().verify(sc.ed25519_sig, sc.command)  # raises if invalid
    rc = command_pb2.RemediationCommand.FromString(sc.command)
    assert rc.device_id == "dev-1" and rc.approval_ref == "dec_1" and rc.WhichOneof("tool") == "terminate"
    assert rc.terminate.process.pid == 4000 and rc.terminate.process.start_time_unix_ms == 123
    assert time.time() < rc.not_after.seconds <= time.time() + 61
    assert sc.key_id == "cmd-test"


def test_validate_incident_rejects_targets_outside_graph():
    body = {"incident": {"incident_id": "inc_" + "d" * 32, "graph": GRAPH, "narrative": "n"}, "proposal": PROPOSAL}
    with pytest.raises(ValueError, match="not in incident graph"):
        validate_incident(body)
    ok = dict(PROPOSAL, steps=PROPOSAL["steps"][:2])
    validate_incident({"incident": body["incident"], "proposal": ok})


def test_audit_chain_detects_tampering():
    rows, prev = [], GENESIS
    for i in range(3):
        h = row_hash(prev, "a", "k", f"s{i}", {"i": i})
        rows.append(("a", "k", f"s{i}", {"i": i}, prev, h))
        prev = h
    assert verify_chain(rows) == (True, None)
    rows[1] = ("a", "k", "s1", {"i": 999}, rows[1][4], rows[1][5])
    assert verify_chain(rows) == (False, 1)


def test_signer_builds_scan_commands():
    from scanu_api.gen import scan_pb2
    from scanu_api.hitl import PlannedCommand

    key = Ed25519PrivateKey.generate()
    s = CommandSigner(key, "cmd-test")
    signed = s.sign(PlannedCommand("start_scan", {"scan_id": "scn_abc", "scope": 2}), device_id="dev-1", action_id="scn_abc", approval_ref="scn_abc")
    rc = command_pb2.RemediationCommand.FromString(command_pb2.SignedCommand.FromString(base64.b64decode(signed.envelope_b64)).command)
    assert rc.WhichOneof("tool") == "start_scan"
    assert rc.start_scan.scan_id == "scn_abc" and rc.start_scan.scope == scan_pb2.SCAN_SCOPE_FULL


def test_profile_validation():
    from pydantic import ValidationError

    from scanu_api.main import ProfileIn

    assert ProfileIn(display_name="Alice", email="a@b.co").email == "a@b.co"
    assert ProfileIn(email="").email == ""
    for bad in ({"email": "not-an-email"}, {"display_name": ""}, {"display_name": "x" * 81}, {"role": "owner"}):
        if "role" in bad:
            assert "role" not in ProfileIn(**bad).model_dump(exclude_none=True), "role is not user-editable"
            continue
        with pytest.raises(ValidationError):
            ProfileIn(**bad)
