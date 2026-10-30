"""Train the edge classifier.

    uv run --group train python train.py --corpus /data/pe --out ../models

Corpus layout: <corpus>/benign/** and <corpus>/malicious/** (raw PE files, e.g.
from your own benign software inventory plus a licensed malware feed). Outputs:
  model.onnx        LightGBM, input "input" f32[N,21], output "probabilities" f32[N,2]
  linear.json       logistic-regression fallback for LinearScorer::from_json
  manifest.json     versions, sha256 of artifacts, held-out metrics
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np

from features import FEATURE_NAMES, extract


def load(corpus: Path) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for label, sub in ((0, "benign"), (1, "malicious")):
        for p in (corpus / sub).rglob("*"):
            if p.is_file() and (f := extract(p.read_bytes())) is not None:
                X.append([f[n] for n in FEATURE_NAMES])
                y.append(label)
    return np.asarray(X, dtype=np.float32), np.asarray(y)


def main() -> None:
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("../models"))
    a = ap.parse_args()
    X, y = load(a.corpus)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=7)

    gbm = lgb.LGBMClassifier(n_estimators=400, num_leaves=31, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8)
    gbm.fit(Xtr, ytr)
    auc = roc_auc_score(yte, gbm.predict_proba(Xte)[:, 1])
    version = f"lgbm-{time.strftime('%Y%m%d')}"
    onx = onnxmltools.convert_lightgbm(gbm, initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
                                       zipmap=False, target_opset=15)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "model.onnx").write_bytes(onx.SerializeToString())

    lr = LogisticRegression(max_iter=2000).fit(Xtr, ytr)
    (a.out / "linear.json").write_text(json.dumps({
        "version": f"linear-{time.strftime('%Y%m%d')}",
        "bias": float(lr.intercept_[0]),
        "weights": dict(zip(FEATURE_NAMES, map(float, lr.coef_[0]))),
    }, indent=2))

    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    (a.out / "manifest.json").write_text(json.dumps({
        "model_version": version,
        "features": FEATURE_NAMES,
        "samples": {"train": int(len(ytr)), "test": int(len(yte)), "malicious_ratio": float(y.mean())},
        "metrics": {"lgbm_auc": float(auc), "linear_auc": float(roc_auc_score(yte, lr.predict_proba(Xte)[:, 1]))},
        "artifacts": {f: sha(a.out / f) for f in ("model.onnx", "linear.json")},
    }, indent=2))
    print(f"{version}: AUC {auc:.4f} on {len(yte)} held-out samples → {a.out}")


if __name__ == "__main__":
    main()
