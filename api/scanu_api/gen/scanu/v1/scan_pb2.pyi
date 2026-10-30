import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ScanScope(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCAN_SCOPE_UNSPECIFIED: _ClassVar[ScanScope]
    SCAN_SCOPE_QUICK: _ClassVar[ScanScope]
    SCAN_SCOPE_FULL: _ClassVar[ScanScope]

class ScanState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SCAN_STATE_UNSPECIFIED: _ClassVar[ScanState]
    SCAN_STATE_RUNNING: _ClassVar[ScanState]
    SCAN_STATE_COMPLETED: _ClassVar[ScanState]
    SCAN_STATE_CANCELLED: _ClassVar[ScanState]
    SCAN_STATE_FAILED: _ClassVar[ScanState]
SCAN_SCOPE_UNSPECIFIED: ScanScope
SCAN_SCOPE_QUICK: ScanScope
SCAN_SCOPE_FULL: ScanScope
SCAN_STATE_UNSPECIFIED: ScanState
SCAN_STATE_RUNNING: ScanState
SCAN_STATE_COMPLETED: ScanState
SCAN_STATE_CANCELLED: ScanState
SCAN_STATE_FAILED: ScanState

class StartScan(_message.Message):
    __slots__ = ("scan_id", "scope")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    scope: ScanScope
    def __init__(self, scan_id: _Optional[str] = ..., scope: _Optional[_Union[ScanScope, str]] = ...) -> None: ...

class CancelScan(_message.Message):
    __slots__ = ("scan_id",)
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    def __init__(self, scan_id: _Optional[str] = ...) -> None: ...

class ScanProgress(_message.Message):
    __slots__ = ("scan_id", "state", "files_seen", "files_analyzed", "bytes_analyzed", "findings", "current_path", "started_at", "finished_at", "error", "scope")
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    FILES_SEEN_FIELD_NUMBER: _ClassVar[int]
    FILES_ANALYZED_FIELD_NUMBER: _ClassVar[int]
    BYTES_ANALYZED_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_PATH_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    FINISHED_AT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    scan_id: str
    state: ScanState
    files_seen: int
    files_analyzed: int
    bytes_analyzed: int
    findings: int
    current_path: str
    started_at: _timestamp_pb2.Timestamp
    finished_at: _timestamp_pb2.Timestamp
    error: str
    scope: ScanScope
    def __init__(self, scan_id: _Optional[str] = ..., state: _Optional[_Union[ScanState, str]] = ..., files_seen: _Optional[int] = ..., files_analyzed: _Optional[int] = ..., bytes_analyzed: _Optional[int] = ..., findings: _Optional[int] = ..., current_path: _Optional[str] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., finished_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., error: _Optional[str] = ..., scope: _Optional[_Union[ScanScope, str]] = ...) -> None: ...
