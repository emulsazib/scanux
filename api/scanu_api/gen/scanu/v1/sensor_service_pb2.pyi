from scanu.v1 import alert_pb2 as _alert_pb2
from scanu.v1 import command_pb2 as _command_pb2
from scanu.v1 import envelope_pb2 as _envelope_pb2
from scanu.v1 import hitl_pb2 as _hitl_pb2
from scanu.v1 import scan_pb2 as _scan_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Hello(_message.Message):
    __slots__ = ("sensor_version", "os", "os_version", "last_seq", "edge_model_version")
    SENSOR_VERSION_FIELD_NUMBER: _ClassVar[int]
    OS_FIELD_NUMBER: _ClassVar[int]
    OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    LAST_SEQ_FIELD_NUMBER: _ClassVar[int]
    EDGE_MODEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    sensor_version: str
    os: str
    os_version: str
    last_seq: int
    edge_model_version: str
    def __init__(self, sensor_version: _Optional[str] = ..., os: _Optional[str] = ..., os_version: _Optional[str] = ..., last_seq: _Optional[int] = ..., edge_model_version: _Optional[str] = ...) -> None: ...

class Heartbeat(_message.Message):
    __slots__ = ("seq", "cpu_percent", "rss_bytes", "driver_connected")
    SEQ_FIELD_NUMBER: _ClassVar[int]
    CPU_PERCENT_FIELD_NUMBER: _ClassVar[int]
    RSS_BYTES_FIELD_NUMBER: _ClassVar[int]
    DRIVER_CONNECTED_FIELD_NUMBER: _ClassVar[int]
    seq: int
    cpu_percent: float
    rss_bytes: int
    driver_connected: bool
    def __init__(self, seq: _Optional[int] = ..., cpu_percent: _Optional[float] = ..., rss_bytes: _Optional[int] = ..., driver_connected: _Optional[bool] = ...) -> None: ...

class StreamRequest(_message.Message):
    __slots__ = ("hello", "batch", "alert", "command_result", "heartbeat", "scan_progress")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    BATCH_FIELD_NUMBER: _ClassVar[int]
    ALERT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_RESULT_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    SCAN_PROGRESS_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    batch: _envelope_pb2.EventBatch
    alert: _alert_pb2.Alert
    command_result: _command_pb2.CommandResult
    heartbeat: Heartbeat
    scan_progress: _scan_pb2.ScanProgress
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., batch: _Optional[_Union[_envelope_pb2.EventBatch, _Mapping]] = ..., alert: _Optional[_Union[_alert_pb2.Alert, _Mapping]] = ..., command_result: _Optional[_Union[_command_pb2.CommandResult, _Mapping]] = ..., heartbeat: _Optional[_Union[Heartbeat, _Mapping]] = ..., scan_progress: _Optional[_Union[_scan_pb2.ScanProgress, _Mapping]] = ...) -> None: ...

class StreamResponse(_message.Message):
    __slots__ = ("command", "prompt", "ack_seq")
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    PROMPT_FIELD_NUMBER: _ClassVar[int]
    ACK_SEQ_FIELD_NUMBER: _ClassVar[int]
    command: _command_pb2.SignedCommand
    prompt: _hitl_pb2.HitlPrompt
    ack_seq: int
    def __init__(self, command: _Optional[_Union[_command_pb2.SignedCommand, _Mapping]] = ..., prompt: _Optional[_Union[_hitl_pb2.HitlPrompt, _Mapping]] = ..., ack_seq: _Optional[int] = ...) -> None: ...

class EnrollRequest(_message.Message):
    __slots__ = ("csr_der",)
    CSR_DER_FIELD_NUMBER: _ClassVar[int]
    csr_der: bytes
    def __init__(self, csr_der: _Optional[bytes] = ...) -> None: ...

class EnrollResponse(_message.Message):
    __slots__ = ("cert_chain_der",)
    CERT_CHAIN_DER_FIELD_NUMBER: _ClassVar[int]
    cert_chain_der: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, cert_chain_der: _Optional[_Iterable[bytes]] = ...) -> None: ...
