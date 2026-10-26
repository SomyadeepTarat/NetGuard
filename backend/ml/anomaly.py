"""Baseline Anomaly Detector for Unknown Attack Patterns.

Combines novelty-mode Local Outlier Factor with statistical feature bounding
fitted on rolling feature windows observed during benign baseline periods.
Explicitly labels outliers as 'ANOMALOUS / UNKNOWN PATTERN', never claiming
unobserved patterns to be confirmed zero-day exploits.
Includes baseline warm-up gating and poison prevention.
"""
from typing import List, Optional
import numpy as np
from sklearn.pipeline import Pipeline
from backend.ml.algorithms import build_novelty_detector, ANOMALY_ALGORITHM
from backend.ml.features import FEATURES


class AnomalyDetector:
    def __init__(self, min_warmup_windows: int = 10, contamination: float = 0.05, random_state: int = 42):
        self._min_warmup_windows = min_warmup_windows
        self._contamination = contamination
        self._random_state = random_state
        self._baseline_buffer: List[List[float]] = []
        if min_warmup_windows < 2 or not 0 < contamination <= .5:
            raise ValueError('LOF needs >=2 warm-up windows and contamination in (0,.5]')
        self._model: Optional[Pipeline] = None
        self._means: Optional[np.ndarray] = None
        self._stds: Optional[np.ndarray] = None
        self._frozen: bool = False
        self._total_evaluated: int = 0
        self._anomalies_detected: int = 0
        self._baseline_samples_seen = 0

    @property
    def is_ready(self) -> bool:
        return self._model is not None and self._means is not None

    @property
    def warmup_progress(self) -> dict:
        return {
            "current_samples": len(self._baseline_buffer),
            "target_samples": self._min_warmup_windows,
            "ready": self.is_ready,
            "frozen": self._frozen,
        }

    def feed_baseline_sample(self, features: dict, force_quarantine: bool = False) -> bool:
        """Admit a screened reference window; screening does not prove benign intent."""
        if self._frozen or force_quarantine:
            return False
        vector = [float(features.get(f, 0.0)) for f in FEATURES]
        if not np.isfinite(vector).all() or min(vector) < 0:
            raise ValueError('Baseline features must be finite and nonnegative')
        self._baseline_buffer.append(vector)
        self._baseline_samples_seen += 1
        if len(self._baseline_buffer) > 512:
            del self._baseline_buffer[0]
        # Re-fit once enough samples gathered, or periodically
        if len(self._baseline_buffer) >= self._min_warmup_windows and (
            self._model is None or self._baseline_samples_seen % 50 == 0
        ):
            self._fit()
        return True

    def _fit(self) -> None:
        if len(self._baseline_buffer) < self._min_warmup_windows:
            return
        raw = np.array(self._baseline_buffer)
        X = np.log1p(raw)
        self._means = np.mean(X, axis=0)
        self._stds = np.maximum(np.std(X, axis=0), 1e-2)
        
        clf = build_novelty_detector(len(raw), self._contamination)
        clf.fit(raw)
        self._model = clf

    def freeze_baseline(self, freeze: bool = True) -> None:
        """Freezes baseline to prevent poisoning during suspicious activity."""
        self._frozen = freeze

    def score(self, features: dict) -> dict:
        self._total_evaluated += 1
        if not self.is_ready or self._model is None or self._means is None or self._stds is None:
            return {
                "status": "WARM_UP",
                "is_anomalous": False,
                "anomaly_score": None,
                "label": "BASELINE_WARMING_UP",
                "progress": f"{len(self._baseline_buffer)}/{self._min_warmup_windows}",
                "note": "Anomaly detector requires warm-up baseline before scoring."
            }

        vector = np.array([float(features.get(f, 0.0)) for f in FEATURES])
        if not np.isfinite(vector).all() or (vector < 0).any():
            raise ValueError('Novelty features must be finite and nonnegative')
        lof_score = float(self._model.decision_function([vector])[0])
        z_scores = np.abs((np.log1p(vector) - self._means) / self._stds)
        max_z = float(np.max(z_scores))

        is_anom = (lof_score < 0.0) or (max_z > 4.5)

        if is_anom:
            self._anomalies_detected += 1

        return {
            "status": "READY",
            "is_anomalous": is_anom,
            "anomaly_score": round(max(max_z / 4.5, -lof_score), 4),
            "lof_score": round(lof_score, 4),
            "algorithm": ANOMALY_ALGORITHM,
            "max_feature_deviation_sigma": round(max_z, 2),
            "label": "ANOMALOUS_UNKNOWN_PATTERN" if is_anom else "NORMAL_BASELINE",
            "note": "Outlier detection relative to benign baseline; does not establish verified zero-day exploit." if is_anom else "Consistent with benign baseline.",
            "progress": "ACTIVE"
        }
