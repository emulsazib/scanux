"""Train/serve skew guard: Python features must equal the Rust extractor's."""

import json
import math
import subprocess
from pathlib import Path

import pytest

from features import FEATURE_NAMES, extract

ROOT = Path(__file__).resolve().parents[3]
CARGO = ["cargo", "run", "-q", "-p", "edge-ml", "--bin", "edgeml", "--"]


def rust(*args: str) -> str:
    return subprocess.run(CARGO + list(args), cwd=ROOT, check=True, capture_output=True, text=True).stdout


@pytest.mark.parametrize("shape", ["benign", "packed"])
def test_features_match_rust(tmp_path, shape):
    sample = tmp_path / f"{shape}.exe"
    rust("synth", shape, str(sample))
    out = json.loads(rust("features", str(sample)))
    r = out["features"]
    p = extract(sample.read_bytes())
    assert p is not None
    assert out["order"] == FEATURE_NAMES, "model input order differs between Rust and Python"
    for name in FEATURE_NAMES:
        assert math.isclose(r[name], p[name], rel_tol=1e-4, abs_tol=1e-4), (name, r[name], p[name])


def test_non_pe_is_none():
    assert extract(b"just text") is None
