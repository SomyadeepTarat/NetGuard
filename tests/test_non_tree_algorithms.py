import joblib
import numpy as np
import pytest
from sklearn.svm import SVC
from sklearn.neighbors import LocalOutlierFactor

from backend.ml.algorithms import build_classifier, build_novelty_detector, CLASSIFIER_ALGORITHM, session_calibration_folds
from backend.ml.anomaly import AnomalyDetector
from backend.ml.detector import Detector
from backend.ml.features import FEATURES, SCHEMA
from backend.ml.evaluate_fusion import fixture_row


def test_classifier_pipeline_round_trip_and_algorithm_contract(tmp_path):
    rng = np.random.default_rng(7)
    rows, labels = [], []
    for label in ('BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'):
        for i in range(12):
            row = fixture_row(rng, i * 5, label)
            rows.append([row['features'][f] for f in FEATURES])
            labels.append(label)
    model = build_classifier().fit(rows, labels)
    assert isinstance(model.estimator.named_steps['classifier'], SVC)
    probabilities = model.predict_proba(rows[:2])
    assert probabilities.shape == (2, 4)
    np.testing.assert_allclose(probabilities.sum(axis=1), 1)
    path = tmp_path / 'model.joblib'
    joblib.dump({'algorithm': CLASSIFIER_ALGORITHM, 'schema': SCHEMA, 'features': FEATURES,
                 'model': model, 'threshold': .8, 'scope': 'test'}, path)
    detector = Detector(path)
    assert detector.model_available
    assert detector.predict(fixture_row(rng, 1000))['model_scope'] == 'test'


def test_unversioned_classifier_artifact_is_rejected(tmp_path):
    path = tmp_path / 'old.joblib'
    joblib.dump({'schema': SCHEMA, 'features': FEATURES, 'model': None, 'threshold': .8}, path)
    with pytest.raises(ValueError, match='retrain'):
        Detector(path)


def test_novelty_pipeline_scores_only_held_out_observations():
    rng = np.random.default_rng(7)
    reference = np.maximum(0, rng.normal(10, .2, (30, len(FEATURES))))
    model = build_novelty_detector(len(reference)).fit(reference)
    assert isinstance(model.named_steps['novelty'], LocalOutlierFactor)
    assert model.named_steps['novelty'].novelty
    held_out = np.maximum(0, rng.normal(10, .1, (1, len(FEATURES))))
    extreme = np.full((1, len(FEATURES)), 10000.)
    assert model.decision_function(held_out)[0] > model.decision_function(extreme)[0]
    assert model.predict(extreme)[0] == -1


def test_anomalous_or_degraded_windows_do_not_enter_reference():
    detector = Detector()
    rng = np.random.default_rng(12)
    for i in range(10):
        row = fixture_row(rng, i * 5)
        detector.anomaly_detector.feed_baseline_sample(row['features'])
    count = len(detector.anomaly_detector._baseline_buffer)
    row = fixture_row(rng, 1000, 'MISSING_RESPONSES')
    assert detector.predict(row)['anomaly']['is_anomalous']
    assert len(detector.anomaly_detector._baseline_buffer) == count
    other = Detector()
    row = fixture_row(rng, 1001)
    row['quality'] = {'queue_drops': 1}
    other.predict(row)
    assert not other.anomaly_detector._baseline_buffer


def test_lof_reference_is_bounded_and_invalid_features_are_rejected():
    anomaly = AnomalyDetector()
    anomaly.freeze_baseline()
    assert not anomaly.feed_baseline_sample({f: 1 for f in FEATURES})
    anomaly.freeze_baseline(False)
    with pytest.raises(ValueError):
        anomaly.feed_baseline_sample({'packets': float('nan')})
    with pytest.raises(ValueError):
        build_novelty_detector(1)


def test_calibration_keeps_capture_groups_together():
    labels, groups = [], []
    for label in ('BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'):
        for capture in range(3):
            labels.extend([label] * 4)
            groups.extend([f'{label}-{capture}'] * 4)
    folds = session_calibration_folds(np.ones((len(labels), 12)), labels, groups)
    for train, validation in folds:
        assert not {groups[i] for i in train} & {groups[i] for i in validation}
        assert {labels[i] for i in train} == set(labels)
