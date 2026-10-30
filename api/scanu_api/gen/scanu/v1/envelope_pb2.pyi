import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Priority(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRIORITY_UNSPECIFIED: _ClassVar[Priority]
    PRIORITY_BULK: _ClassVar[Priority]
    PRIORITY_SIGNAL: _ClassVar[Priority]
    PRIORITY_CRITICAL: _ClassVar[Priority]
PRIORITY_UNSPECIFIED: Priority
PRIORITY_BULK: Priority
PRIORITY_SIGNAL: Priority
PRIORITY_CRITICAL: Priority

class EventEnvelope(_message.Message):
    __slots__ = ("event_id", "device_id", "observed_at", "ocsf_class_uid", "ocsf_json", "seq", "priority")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_AT_FIELD_NUMBER: _ClassVar[int]
    OCSF_CLASS_UID_FIELD_NUMBER: _ClassVar[int]
    OCSF_JSON_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    device_id: str
    observed_at: _timestamp_pb2.Timestamp
    ocsf_class_uid: int
    ocsf_json: bytes
    seq: int
    priority: Priority
    def __init__(self, event_id: _Optional[str] = ..., device_id: _Optional[str] = ..., observed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ocsf_class_uid: _Optional[int] = ..., ocsf_json: _Optional[bytes] = ..., seq: _Optional[int] = ..., priority: _Optional[_Union[Priority, str]] = ...) -> None: ...

class EventBatch(_message.Message):
    __slots__ = ("events", "dropped_since_last")
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    DROPPED_SINCE_LAST_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[EventEnvelope]
    dropped_since_last: int
    def __init__(self, events: _Optional[_Iterable[_Union[EventEnvelope, _Mapping]]] = ..., dropped_since_last: _Optional[int] = ...) -> None: ...
