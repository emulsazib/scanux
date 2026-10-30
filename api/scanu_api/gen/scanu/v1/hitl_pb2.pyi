import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ActionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACTION_STATE_UNSPECIFIED: _ClassVar[ActionState]
    ACTION_STATE_PROPOSED: _ClassVar[ActionState]
    ACTION_STATE_APPROVED: _ClassVar[ActionState]
    ACTION_STATE_REJECTED: _ClassVar[ActionState]
    ACTION_STATE_EXECUTED: _ClassVar[ActionState]
    ACTION_STATE_VERIFIED: _ClassVar[ActionState]
    ACTION_STATE_FAILED: _ClassVar[ActionState]
    ACTION_STATE_ROLLED_BACK: _ClassVar[ActionState]

class UserChoice(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    USER_CHOICE_UNSPECIFIED: _ClassVar[UserChoice]
    USER_CHOICE_TERMINATE_AND_QUARANTINE: _ClassVar[UserChoice]
    USER_CHOICE_ISOLATE_NETWORK_ONLY: _ClassVar[UserChoice]
    USER_CHOICE_ALLOW_AND_WHITELIST: _ClassVar[UserChoice]
ACTION_STATE_UNSPECIFIED: ActionState
ACTION_STATE_PROPOSED: ActionState
ACTION_STATE_APPROVED: ActionState
ACTION_STATE_REJECTED: ActionState
ACTION_STATE_EXECUTED: ActionState
ACTION_STATE_VERIFIED: ActionState
ACTION_STATE_FAILED: ActionState
ACTION_STATE_ROLLED_BACK: ActionState
USER_CHOICE_UNSPECIFIED: UserChoice
USER_CHOICE_TERMINATE_AND_QUARANTINE: UserChoice
USER_CHOICE_ISOLATE_NETWORK_ONLY: UserChoice
USER_CHOICE_ALLOW_AND_WHITELIST: UserChoice

class HitlPrompt(_message.Message):
    __slots__ = ("action_id", "incident_id", "title", "explanation", "choices", "expires_at")
    ACTION_ID_FIELD_NUMBER: _ClassVar[int]
    INCIDENT_ID_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    EXPLANATION_FIELD_NUMBER: _ClassVar[int]
    CHOICES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    action_id: str
    incident_id: str
    title: str
    explanation: str
    choices: _containers.RepeatedScalarFieldContainer[UserChoice]
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, action_id: _Optional[str] = ..., incident_id: _Optional[str] = ..., title: _Optional[str] = ..., explanation: _Optional[str] = ..., choices: _Optional[_Iterable[_Union[UserChoice, str]]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HitlDecision(_message.Message):
    __slots__ = ("decision_id", "action_id", "choice", "user_id", "channel", "decided_at", "webauthn_assertion")
    DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_ID_FIELD_NUMBER: _ClassVar[int]
    CHOICE_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    DECIDED_AT_FIELD_NUMBER: _ClassVar[int]
    WEBAUTHN_ASSERTION_FIELD_NUMBER: _ClassVar[int]
    decision_id: str
    action_id: str
    choice: UserChoice
    user_id: str
    channel: str
    decided_at: _timestamp_pb2.Timestamp
    webauthn_assertion: bytes
    def __init__(self, decision_id: _Optional[str] = ..., action_id: _Optional[str] = ..., choice: _Optional[_Union[UserChoice, str]] = ..., user_id: _Optional[str] = ..., channel: _Optional[str] = ..., decided_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., webauthn_assertion: _Optional[bytes] = ...) -> None: ...
