import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from scanu.v1 import alert_pb2 as _alert_pb2
from scanu.v1 import scan_pb2 as _scan_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CommandStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COMMAND_STATUS_UNSPECIFIED: _ClassVar[CommandStatus]
    COMMAND_STATUS_EXECUTED: _ClassVar[CommandStatus]
    COMMAND_STATUS_REJECTED: _ClassVar[CommandStatus]
    COMMAND_STATUS_FAILED: _ClassVar[CommandStatus]
COMMAND_STATUS_UNSPECIFIED: CommandStatus
COMMAND_STATUS_EXECUTED: CommandStatus
COMMAND_STATUS_REJECTED: CommandStatus
COMMAND_STATUS_FAILED: CommandStatus

class SuspendProcess(_message.Message):
    __slots__ = ("process",)
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    process: _alert_pb2.ProcessRef
    def __init__(self, process: _Optional[_Union[_alert_pb2.ProcessRef, _Mapping]] = ...) -> None: ...

class ResumeProcess(_message.Message):
    __slots__ = ("process",)
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    process: _alert_pb2.ProcessRef
    def __init__(self, process: _Optional[_Union[_alert_pb2.ProcessRef, _Mapping]] = ...) -> None: ...

class TerminateProcess(_message.Message):
    __slots__ = ("process",)
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    process: _alert_pb2.ProcessRef
    def __init__(self, process: _Optional[_Union[_alert_pb2.ProcessRef, _Mapping]] = ...) -> None: ...

class BlockProcessNetwork(_message.Message):
    __slots__ = ("process",)
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    process: _alert_pb2.ProcessRef
    def __init__(self, process: _Optional[_Union[_alert_pb2.ProcessRef, _Mapping]] = ...) -> None: ...

class UnblockProcessNetwork(_message.Message):
    __slots__ = ("process",)
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    process: _alert_pb2.ProcessRef
    def __init__(self, process: _Optional[_Union[_alert_pb2.ProcessRef, _Mapping]] = ...) -> None: ...

class QuarantineFile(_message.Message):
    __slots__ = ("path", "sha256")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    path: str
    sha256: str
    def __init__(self, path: _Optional[str] = ..., sha256: _Optional[str] = ...) -> None: ...

class RestoreFromVault(_message.Message):
    __slots__ = ("vault_id",)
    VAULT_ID_FIELD_NUMBER: _ClassVar[int]
    vault_id: str
    def __init__(self, vault_id: _Optional[str] = ...) -> None: ...

class AllowlistHash(_message.Message):
    __slots__ = ("sha256",)
    SHA256_FIELD_NUMBER: _ClassVar[int]
    sha256: str
    def __init__(self, sha256: _Optional[str] = ...) -> None: ...

class RemediationCommand(_message.Message):
    __slots__ = ("command_id", "action_id", "device_id", "not_after", "nonce", "approval_ref", "suspend", "resume", "terminate", "net_block", "net_unblock", "quarantine", "restore", "allowlist", "start_scan", "cancel_scan")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REF_FIELD_NUMBER: _ClassVar[int]
    SUSPEND_FIELD_NUMBER: _ClassVar[int]
    RESUME_FIELD_NUMBER: _ClassVar[int]
    TERMINATE_FIELD_NUMBER: _ClassVar[int]
    NET_BLOCK_FIELD_NUMBER: _ClassVar[int]
    NET_UNBLOCK_FIELD_NUMBER: _ClassVar[int]
    QUARANTINE_FIELD_NUMBER: _ClassVar[int]
    RESTORE_FIELD_NUMBER: _ClassVar[int]
    ALLOWLIST_FIELD_NUMBER: _ClassVar[int]
    START_SCAN_FIELD_NUMBER: _ClassVar[int]
    CANCEL_SCAN_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    action_id: str
    device_id: str
    not_after: _timestamp_pb2.Timestamp
    nonce: int
    approval_ref: str
    suspend: SuspendProcess
    resume: ResumeProcess
    terminate: TerminateProcess
    net_block: BlockProcessNetwork
    net_unblock: UnblockProcessNetwork
    quarantine: QuarantineFile
    restore: RestoreFromVault
    allowlist: AllowlistHash
    start_scan: _scan_pb2.StartScan
    cancel_scan: _scan_pb2.CancelScan
    def __init__(self, command_id: _Optional[str] = ..., action_id: _Optional[str] = ..., device_id: _Optional[str] = ..., not_after: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., nonce: _Optional[int] = ..., approval_ref: _Optional[str] = ..., suspend: _Optional[_Union[SuspendProcess, _Mapping]] = ..., resume: _Optional[_Union[ResumeProcess, _Mapping]] = ..., terminate: _Optional[_Union[TerminateProcess, _Mapping]] = ..., net_block: _Optional[_Union[BlockProcessNetwork, _Mapping]] = ..., net_unblock: _Optional[_Union[UnblockProcessNetwork, _Mapping]] = ..., quarantine: _Optional[_Union[QuarantineFile, _Mapping]] = ..., restore: _Optional[_Union[RestoreFromVault, _Mapping]] = ..., allowlist: _Optional[_Union[AllowlistHash, _Mapping]] = ..., start_scan: _Optional[_Union[_scan_pb2.StartScan, _Mapping]] = ..., cancel_scan: _Optional[_Union[_scan_pb2.CancelScan, _Mapping]] = ...) -> None: ...

class SignedCommand(_message.Message):
    __slots__ = ("command", "ed25519_sig", "key_id")
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    ED25519_SIG_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    command: bytes
    ed25519_sig: bytes
    key_id: str
    def __init__(self, command: _Optional[bytes] = ..., ed25519_sig: _Optional[bytes] = ..., key_id: _Optional[str] = ...) -> None: ...

class CommandResult(_message.Message):
    __slots__ = ("command_id", "action_id", "status", "reason", "vault_id", "completed_at")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    VAULT_ID_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_AT_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    action_id: str
    status: CommandStatus
    reason: str
    vault_id: str
    completed_at: _timestamp_pb2.Timestamp
    def __init__(self, command_id: _Optional[str] = ..., action_id: _Optional[str] = ..., status: _Optional[_Union[CommandStatus, str]] = ..., reason: _Optional[str] = ..., vault_id: _Optional[str] = ..., completed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
