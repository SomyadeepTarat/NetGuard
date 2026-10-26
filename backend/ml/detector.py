"""Trustworthy Multi-Path Threat Detection and Evidence Fusion.

Combines:
1. Explainable rule paths with explicit thresholds, units, and measured values.
2. Supervised 4-class RBF SVM (class score, not verified attack probability).
3. Benign baseline anomaly detector for outlier/unknown patterns.
4. Capture-quality gating (degraded observation marks findings UNCERTAIN, never benign).
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
from backend.ml.features import FEATURES, SCHEMA
from backend.ml.fragility import handshake_fragility
from backend.ml.anomaly import AnomalyDetector
from backend.ml.evidence_fusion import EvidenceFusionEngine
from backend.ml.algorithms import CLASSIFIER_ALGORITHM, is_supported_classifier

EXPLAINABLE_RULES = [
    {
        "rule_id": "RULE-SCAN-01",
        "name": "Rapid Destination Port Sweep",
        "attack_class": "PORT_SCAN",
        "description": "High unique destination port diversity combined with elevated outbound SYN rate.",
        "condition": lambda f: f.get("unique_ports", 0) >= 15 and f.get("syn_rate", 0) >= 2,
        "thresholds": {"unique_ports": ">= 15 ports", "syn_rate": ">= 2.0 pkts/s"},
        "units": {"unique_ports": "distinct ports", "syn_rate": "packets/sec"},
    },
    {
        "rule_id": "RULE-SYN-01",
        "name": "High-Rate SYN Incompletion",
        "attack_class": "SYN_FLOOD",
        "description": "Sustained high SYN transmission rate with negligible handshake completion ratio.",
        "condition": lambda f: f.get("syn_rate", 0) >= 30 and f.get("completed_fraction", 0) < 0.1,
        "thresholds": {"syn_rate": ">= 30.0 pkts/s", "completed_fraction": "< 0.10 (10%)"},
        "units": {"syn_rate": "packets/sec", "completed_fraction": "ratio (0.0 to 1.0)"},
    },
    {
        "rule_id": "RULE-FLOOD-01",
        "name": "Volumetric Traffic Surge",
        "attack_class": "TRAFFIC_FLOOD",
        "description": "Sustained high byte throughput exceeding the baseline traffic threshold.",
        "condition": lambda f: f.get("bytes_per_second", 0) >= 80000,
        "thresholds": {"bytes_per_second": ">= 80,000 bytes/s"},
        "units": {"bytes_per_second": "bytes/sec"},
    },
]


def baseline(features: dict) -> str:
    """Transparent deterministic rule baseline contract."""
    if features.get('unique_ports', 0) >= 15 and features.get('syn_rate', 0) >= 2:
        return 'PORT_SCAN'
    if features.get('syn_rate', 0) >= 30 and features.get('completed_fraction', 0) < .1:
        return 'SYN_FLOOD'
    if features.get('bytes_per_second', 0) >= 80000:
        return 'TRAFFIC_FLOOD'
    return 'BENIGN'


def evaluate_rules(features: dict) -> List[dict]:
    """Returns detailed evaluation for every explainable rule."""
    results = []
    for r in EXPLAINABLE_RULES:
        triggered = bool(r["condition"](features))
        measured = {}
        for key in r["thresholds"].keys():
            measured[key] = round(float(features.get(key, 0.0)), 4)
        results.append({
            "rule_id": r["rule_id"],
            "name": r["name"],
            "attack_class": r["attack_class"],
            "description": r["description"],
            "thresholds": r["thresholds"],
            "units": r["units"],
            "measured_values": measured,
            "triggered": triggered,
        })
    return results


class Detector:
    def __init__(self, model_path: Optional[str] = None, threshold: Optional[float] = None, anomaly_detector: Optional[AnomalyDetector] = None):
        self.bundle = None
        self.threshold = 0.8
        self.model_available = False
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.fusion_engine = EvidenceFusionEngine()

        if model_path is not None:
            p = Path(model_path)
            if p.exists():
                self.bundle = joblib.load(p)
                if self.bundle.get('algorithm') != CLASSIFIER_ALGORITHM or not is_supported_classifier(self.bundle.get('model')):
                    raise ValueError('Unsupported classifier artifact; retrain with python -m backend.ml train --manifest artifacts/demo/manifest.json')
                if self.bundle.get('schema') != SCHEMA or self.bundle.get('features') != FEATURES:
                    raise ValueError('Model feature schema mismatch; retrain the model')
                self.threshold = self.bundle['threshold'] if threshold is None else threshold
                if not 0 <= self.threshold <= 1:
                    raise ValueError('Threshold must be between zero and one')
                self.model_available = True
            else:
                self.model_available = False

    def predict(self, row: dict) -> dict:
        features = row['features']
        quality = row.get('quality', {})
        degraded = bool(any(quality.get(k) for k in ('state_evictions', 'late_packets', 'queue_drops', 'parser_errors')))
        rule_class = baseline(features)
        detailed_rules = evaluate_rules(features)
        triggered_rules = [r for r in detailed_rules if r["triggered"]]

        model_class = "BENIGN"
        score = 0.0
        model_scope = "model_unavailable"
        fragility = {
            'status': 'not_applicable',
            'advisory_only': True,
            'reason': 'Model unavailable or requires a SYN_FLOOD prediction above score threshold'
        }

        model_available = getattr(self, 'model_available', False) or (getattr(self, 'bundle', None) is not None and 'model' in getattr(self, 'bundle', {}))
        anomaly_detector = getattr(self, 'anomaly_detector', None)

        if model_available and getattr(self, 'bundle', None):
            model = self.bundle['model']
            probabilities = model.predict_proba([[features[f] for f in FEATURES]])[0]
            index = probabilities.argmax()
            model_class, score = str(model.classes_[index]), float(probabilities[index])
            model_scope = self.bundle.get('scope', 'local-artifact')

            if model_class == 'SYN_FLOOD' and score >= self.threshold:
                fragility = handshake_fragility(model, row, self.threshold)

        # Baseline anomaly detector scoring
        if anomaly_detector is not None:
            anomaly_result = anomaly_detector.score(features)
            if model_class == 'BENIGN' and rule_class == 'BENIGN' and not anomaly_result.get('is_anomalous') and not degraded:
                anomaly_detector.feed_baseline_sample(features)
            else:
                anomaly_detector.freeze_baseline(True)
        else:
            anomaly_result = {
                "status": "UNAVAILABLE", "is_anomalous": False,
                "anomaly_score": None, "label": "DETECTOR_DISABLED",
                "note": "Anomaly detector not attached."
            }

        engine = getattr(self, 'fusion_engine', None)
        research = engine.score(row, allow_reference=(rule_class == 'BENIGN' and model_class == 'BENIGN'
                                and not anomaly_result.get('is_anomalous') and not degraded)) if engine else {
            'status': 'UNAVAILABLE', 'is_anomalous': False}

        # Primary decision determination
        if model_available:
            decision = 'BENIGN' if model_class == 'BENIGN' else ('SUSPECTED' if score >= self.threshold else 'UNCERTAIN')
        else:
            # Fallback to rule path if model unavailable
            decision = 'BENIGN' if rule_class == 'BENIGN' else 'SUSPECTED'

        prediction = model_class if model_available else rule_class
        # Preserve explicit rule evidence even when a classifier votes benign.
        if rule_class != 'BENIGN' and decision == 'BENIGN':
            prediction, decision = rule_class, 'UNCERTAIN'
        if research.get('is_anomalous') and decision == 'BENIGN':
            prediction, decision = 'ANOMALOUS_UNKNOWN_PATTERN', 'SUSPECTED'
        elif anomaly_result.get('is_anomalous') and decision == 'BENIGN':
            prediction, decision = 'ANOMALOUS_UNKNOWN_PATTERN', 'UNCERTAIN'

        # Capture quality degradation safeguard
        if degraded or (prediction == 'ANOMALOUS_UNKNOWN_PATTERN' and
                        research.get('visibility', {}).get('status') == 'SENSITIVE'):
            if decision == 'SUSPECTED':
                decision = 'UNCERTAIN'

        # Evidence fusion & corroboration
        corroborated = (rule_class == model_class and model_class != 'BENIGN')
        if not model_available:
            corroborated = (rule_class != 'BENIGN')

        agreement_status = "AGREED_BENIGN"
        if model_class != "BENIGN" and rule_class != "BENIGN":
            agreement_status = "FULL_AGREEMENT" if model_class == rule_class else "CLASS_DISCREPANCY"
        elif model_class != "BENIGN" and rule_class == "BENIGN":
            agreement_status = "MODEL_ONLY"
        elif model_class == "BENIGN" and rule_class != "BENIGN":
            agreement_status = "RULE_ONLY"

        fusion = {
            "model_prediction": model_class if model_available else "UNAVAILABLE",
            "model_score": round(score, 4) if model_available else None,
            "is_calibrated": False,
            "rule_prediction": rule_class,
            "triggered_rules": [r["rule_id"] for r in triggered_rules],
            "anomaly_status": anomaly_result["label"],
            "agreement_status": agreement_status,
            "evidence_quality": "DEGRADED" if degraded else "NO_KNOWN_INTERNAL_LOSS",
        }

        return {
            **row,
            'prediction': prediction,
            'score': score,
            'decision': decision,
            'fragility': fragility,
            'baseline': rule_class,
            'corroborated': corroborated,
            'model_scope': model_scope,
            'model_available': model_available,
            'detailed_rules': detailed_rules,
            'anomaly': anomaly_result,
            'fusion': fusion,
            'research_fusion': research,
            'evidence': {
                k: round(features[k], 4)
                for k in ('syn_rate', 'unique_ports', 'completed_fraction', 'bytes_per_second', 'response_fraction')
                if k in features
            }
        }


class JsonOutput:
    def __init__(self, path):
        self.file = Path(path).open('w')

    def emit(self, record):
        self.file.write(json.dumps(record) + '\n')
        self.file.flush()

    def close(self):
        self.file.close()
