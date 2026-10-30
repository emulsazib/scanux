"""Builds and Ed25519-signs RemediationCommands. In production the private key
lives in KMS/HSM behind a sign-only identity; dev loads the PEM from devpki."""

from __future__ import annotations

import base64
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf.timestamp_pb2 import Timestamp

from .gen import alert_pb2, command_pb2, scan_pb2
from .hitl import PlannedCommand

_TOOLS = {
    "suspend": ("suspend", command_pb2.SuspendProcess),
    "resume": ("resume", command_pb2.ResumeProcess),
    "terminate": ("terminate", command_pb2.TerminateProcess),
    "net_block": ("net_block", command_pb2.BlockProcessNetwork),
    "net_unblock": ("net_unblock", command_pb2.UnblockProcessNetwork),
    "quarantine": ("quarantine", command_pb2.QuarantineFile),
    "restore": ("restore", command_pb2.RestoreFromVault),
    "allowlist": ("allowlist", command_pb2.AllowlistHash),
    "start_scan": ("start_scan", scan_pb2.StartScan),
    "cancel_scan": ("cancel_scan", scan_pb2.CancelScan),
}


@dataclass(frozen=True)
class Signed:
    command_id: str
    nonce: int
    not_after_s: int
    envelope_b64: str  # base64(SignedCommand)


class CommandSigner:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str, ttl_s: int = 300):
        self._key = private_key
        self.key_id = key_id
        self.ttl_s = ttl_s

    @classmethod
    def from_pki_dir(cls, pki: str | Path, ttl_s: int = 300) -> "CommandSigner":
        pki = Path(pki)
        key = serialization.load_pem_private_key((pki / "cmd-signing.key.pem").read_bytes(), password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return cls(key, (pki / "cmd-signing.key_id").read_text().strip(), ttl_s)

    def sign(self, cmd: PlannedCommand, *, device_id: str, action_id: str, approval_ref: str) -> Signed:
        field, msg_type = _TOOLS[cmd.tool]
        rc = command_pb2.RemediationCommand(
            command_id=f"cmd_{uuid.uuid4().hex}",
            action_id=action_id,
            device_id=device_id,
            nonce=secrets.randbits(63),
            approval_ref=approval_ref,
        )
        not_after = int(time.time()) + self.ttl_s
        rc.not_after.CopyFrom(Timestamp(seconds=not_after))
        args = dict(cmd.args)
        if "process" in args:
            args["process"] = alert_pb2.ProcessRef(**args["process"])
        getattr(rc, field).CopyFrom(msg_type(**args))
        body = rc.SerializeToString()
        sc = command_pb2.SignedCommand(command=body, ed25519_sig=self._key.sign(body), key_id=self.key_id)
        return Signed(rc.command_id, rc.nonce, not_after, base64.b64encode(sc.SerializeToString()).decode())
