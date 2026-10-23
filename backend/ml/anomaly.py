"""Baseline Anomaly Detector for Unknown Attack Patterns.

Combines an Isolation Forest with statistical baseline feature bounding (z-score envelope)
fitted on rolling feature windows observed during benign baseline periods.
Explicitly labels outliers as 'ANOMALOUS / UNKNOWN PATTERN', never claiming
unobserved patterns to be confirmed zero-day exploits.
Includes baseline warm-up gating and poison prevention.
"""
from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from backend.ml.features import FEATURES


class AnomalyDetector:
    def __init__(self, min_warmup_windows: int = 10, contamination: float = 0.05, random_state: int = 42):
        self._min_warmup_windows = min_warmup_windows
        self._contamination = contamination
        self._random_state = random_state
        self._baseline_buffer: List[List[float]] = []
        self._model: Optional[IsolationForest] = None
        self._means: Optional[np.ndarray] = None
        self._stds: Optional[np.ndarray] = None
        self._frozen: bool = False
        self._total_evaluated: int = 0
        self._anomalies_detected: int = 0

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
        """Add a verified benign window to baseline. Quarantines if suspicious to prevent poisoning."""
        if self._frozen or force_quarantine:
            return False
        vector = [float(features.get(f, 0.0)) for f in FEATURES]
        self._baseline_buffer.append(vector)
        # Re-fit once enough samples gathered, or periodically
        if len(self._baseline_buffer) >= self._min_warmup_windows and (
            self._model is None or len(self._baseline_buffer) % 50 == 0
        ):
            self._fit()
        return True

    def _fit(self) -> None:
        if len(self._baseline_buffer) < self._min_warmup_windows:
            return
        X = np.array(self._baseline_buffer)
        self._means = np.mean(X, axis=0)
        self._stds = np.maximum(np.std(X, axis=0), 1e-2)
        
        # Fit Isolation Forest with appropriate max_samples
        max_samples = min(len(X), 256)
        clf = IsolationForest(
            n_estimators=100,
            max_samples=max_samples,
            contamination=self._contamination,
            random_state=self._random_state,
            n_jobs=1
        )
        clf.fit(X)
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
        forest_score = float(self._model.decision_function([vector])[0])
        z_scores = np.abs((vector - self._means) / self._stds)
        max_z = float(np.max(z_scores))

        # Flagged if IsolationForest decision function < 0 or any feature deviates > 4.5 sigma
        is_anom = (forest_score < 0.0) or (max_z > 4.5)

        if is_anom:
            self._anomalies_detected += 1

        return {
            "status": "READY",
            "is_anomalous": is_anom,
            "anomaly_score": round(max_z if max_z > 4.5 else forest_score, 4),
            "forest_score": round(forest_score, 4),
            "max_feature_deviation_sigma": round(max_z, 2),
            "label": "ANOMALOUS_UNKNOWN_PATTERN" if is_anom else "NORMAL_BASELINE",
            "note": "Outlier detection relative to benign baseline; does not establish verified zero-day exploit." if is_anom else "Consistent with benign baseline.",
            "progress": "ACTIVE"
        }
