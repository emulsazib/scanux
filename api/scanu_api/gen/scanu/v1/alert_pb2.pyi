import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_UNSPECIFIED: _ClassVar[Severity]
    SEVERITY_LOW: _ClassVar[Severity]
    SEVERITY_MEDIUM: _ClassVar[Severity]
    SEVERITY_HIGH: _ClassVar[Severity]
    SEVERITY_CRITICAL: _ClassVar[Severity]

class FreezeState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FREEZE_STATE_UNSPECIFIED: _ClassVar[FreezeState]
    FREEZE_STATE_NONE: _ClassVar[FreezeState]
    FREEZE_STATE_SUSPENDED: _ClassVar[FreezeState]
    FREEZE_STATE_NET_BLOCKED: _ClassVar[FreezeState]
    FREEZE_STATE_SUSPENDED_AND_NET_BLOCKED: _ClassVar[FreezeState]
SEVERITY_UNSPECIFIED: Severity
SEVERITY_LOW: Severity
SEVERITY_MEDIUM: Severity
SEVERITY_HIGH: Severity
SEVERITY_CRITICAL: Severity
FREEZE_STATE_UNSPECIFIED: FreezeState
FREEZE_STATE_NONE: FreezeState
FREEZE_STATE_SUSPENDED: FreezeState
FREEZE_STATE_NET_BLOCKED: FreezeState
FREEZE_STATE_SUSPENDED_AND_NET_BLOCKED: FreezeState

class ProcessRef(_message.Message):
    __slots__ = ("pid", "start_time_unix_ms", "image_path", "sha256", "parent_pid")
    PID_FIELD_NUMBER: _ClassVar[int]
    START_TIME_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_PATH_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    PARENT_PID_FIELD_NUMBER: _ClassVar[int]
    pid: int
    start_time_unix_ms: int
    image_path: str
    sha256: str
    parent_pid: int
    def __init__(self, pid: _Optional[int] = ..., start_time_unix_ms: _Optional[int] = ..., image_path: _Optional[str] = ..., sha256: _Optional[str] = ..., parent_pid: _Optional[int] = ...) -> None: ...

class BloomHit(_message.Message):
    __slots__ = ("sha256", "feed")
    SHA256_FIELD_NUMBER: _ClassVar[int]
    FEED_FIELD_NUMBER: _ClassVar[int]
    sha256: str
    feed: str
    def __init__(self, sha256: _Optional[str] = ..., feed: _Optional[str] = ...) -> None: ...

class MlVerdict(_message.Message):
    __slots__ = ("model_version", "score", "top_features")
    MODEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    TOP_FEATURES_FIELD_NUMBER: _ClassVar[int]
    model_version: str
    score: float
    top_features: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, model_version: _Optional[str] = ..., score: _Optional[float] = ..., top_features: _Optional[_Iterable[str]] = ...) -> None: ...

class CanaryTrip(_message.Message):
    __slots__ = ("canary_id", "operation", "trip_us", "frozen_us")
    CANARY_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    TRIP_US_FIELD_NUMBER: _ClassVar[int]
    FROZEN_US_FIELD_NUMBER: _ClassVar[int]
    canary_id: str
    operation: str
    trip_us: int
    frozen_us: int
    def __init__(self, canary_id: _Optional[str] = ..., operation: _Optional[str] = ..., trip_us: _Optional[int] = ..., frozen_us: _Optional[int] = ...) -> None: ...

class YaraMatch(_message.Message):
    __slots__ = ("rules",)
    RULES_FIELD_NUMBER: _ClassVar[int]
    rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, rules: _Optional[_Iterable[str]] = ...) -> None: ...

class Heuristic(_message.Message):
    __slots__ = ("name", "score", "detail")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    name: str
    score: float
    detail: str
    def __init__(self, name: _Optional[str] = ..., score: _Optional[float] = ..., detail: _Optional[str] = ...) -> None: ...

class Alert(_message.Message):
    __slots__ = ("alert_id", "device_id", "event_ids", "severity", "confidence", "raised_at", "bloom", "ml", "canary", "yara", "heuristic", "tier1", "process", "file_path", "file_sha256", "scan_id")
    ALERT_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_IDS_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    RAISED_AT_FIELD_NUMBER: _ClassVar[int]
    BLOOM_FIELD_NUMBER: _ClassVar[int]
    ML_FIELD_NUMBER: _ClassVar[int]
    CANARY_FIELD_NUMBER: _ClassVar[int]
    YARA_FIELD_NUMBER: _ClassVar[int]
    HEURISTIC_FIELD_NUMBER: _ClassVar[int]
    TIER1_FIELD_NUMBER: _ClassVar[int]
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    FILE_SHA256_FIELD_NUMBER: _ClassVar[int]
    SCAN_ID_FIELD_NUMBER: _ClassVar[int]
    alert_id: str
    device_id: str
    event_ids: _containers.RepeatedScalarFieldContainer[str]
    severity: Severity
    confidence: float
    raised_at: _timestamp_pb2.Timestamp
    bloom: BloomHit
    ml: MlVerdict
    canary: CanaryTrip
    yara: YaraMatch
    heuristic: Heuristic
    tier1: FreezeState
    process: ProcessRef
    file_path: str
    file_sha256: str
    scan_id: str
    def __init__(self, alert_id: _Optional[str] = ..., device_id: _Optional[str] = ..., event_ids: _Optional[_Iterable[str]] = ..., severity: _Optional[_Union[Severity, str]] = ..., confidence: _Optional[float] = ..., raised_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., bloom: _Optional[_Union[BloomHit, _Mapping]] = ..., ml: _Optional[_Union[MlVerdict, _Mapping]] = ..., canary: _Optional[_Union[CanaryTrip, _Mapping]] = ..., yara: _Optional[_Union[YaraMatch, _Mapping]] = ..., heuristic: _Optional[_Union[Heuristic, _Mapping]] = ..., tier1: _Optional[_Union[FreezeState, str]] = ..., process: _Optional[_Union[ProcessRef, _Mapping]] = ..., file_path: _Optional[str] = ..., file_sha256: _Optional[str] = ..., scan_id: _Optional[str] = ...) -> None: ...
