"""protoc output for schemas/proto (regenerate with `make proto`).

The generated modules import each other as `scanu.v1.*`, so this directory is
put on sys.path.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from scanu.v1 import alert_pb2, command_pb2, hitl_pb2, scan_pb2  # noqa: E402

__all__ = ["alert_pb2", "command_pb2", "hitl_pb2", "scan_pb2"]
