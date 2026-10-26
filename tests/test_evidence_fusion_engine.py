from dataclasses import replace
import json
import numpy as np
import pytest

from backend.ml.evidence_fusion import EvidenceFusionEngine, FusionConfig
from backend.ml.evaluate_fusion import fixture_row, synthetic_data
from backend.ml.detector import Detector
from backend.services.replay_lab import clone_isolated_detector


@pytest.fixture
def reference():
    config = FusionConfig(fit_windows=16, calibration_windows=32)
    return config, synthetic_data(11, config)[0]


def test_reference_is_split_frozen_and_repeatable(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(config)
    with pytest.raises(ValueError):
        engine.fit_reference(rows[:10])
    engine.fit_reference(rows)
    digest = engine.reference_digest
    clone = engine.fresh()
    row = fixture_row(np.random.default_rng(99), 10000, 'PORT_SCAN')
    assert engine.score(row) == clone.score(row)
    assert engine.reference_digest == digest
    assert len(engine.reference) == 48
    assert engine.states is not clone.states


def test_reference_admission_rejects_suspicious_and_subsamples_overlap(reference):
    config, _ = reference
    engine = EvidenceFusionEngine(config)
    rng = np.random.default_rng(12)
    for t in range(15):
        engine.score(fixture_row(rng, t), allow_reference=True)
    assert len(engine.reference) == 3
    engine.score(fixture_row(rng, 20, 'SYN_FLOOD'), allow_reference=False)
    assert len(engine.reference) == 3
    assert engine.rejected_reference_windows == 1


def test_peer_novelty_adds_evidence_without_changing_flow_features(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(config)
    engine.fit_reference(rows)
    base = fixture_row(np.random.default_rng(1), 10000)
    novel = {**base, 'graph_context': {'out_degree': 2, 'edges': ['unknown-a|445|TCP', 'unknown-b|3389|TCP']}}
    assert engine.score(novel)['graph_p_value'] < engine.fresh().score(base)['graph_p_value']
    no_graph = EvidenceFusionEngine(replace(config, graph_enabled=False))
    no_graph.fit_reference(rows)
    assert no_graph.score(novel)['graph_score'] == 0


def test_temporal_evidence_needs_separated_persistent_windows(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(config)
    engine.fit_reference(rows)
    rng = np.random.default_rng(1)
    first = fixture_row(rng, 10000, 'SYN_FLOOD')
    result = engine.score(first)
    assert result['instant_candidate'] and not result['is_anomalous']
    previous = result['temporal_evidence']
    for t in (10001, 10002, 10003):
        duplicate = engine.score({**first, 'timestamp': t})
        assert not duplicate['temporal_updated']
        assert duplicate['temporal_evidence'] == previous
    for t in range(10005, 10035, 5):
        result = engine.score(fixture_row(rng, t, 'SYN_FLOOD'))
    assert result['is_anomalous']
    after_gap = engine.score(fixture_row(rng, 10100, 'SYN_FLOOD'))
    assert not after_gap['is_anomalous']


def test_visibility_mask_flags_response_only_departure(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(config)
    engine.fit_reference(rows)
    row = fixture_row(np.random.default_rng(4), 10000, 'MISSING_RESPONSES')
    result = engine.score(row)
    assert result['visibility']['status'] == 'SENSITIVE'
    assert result['visibility']['masked_p_value'] > config.alpha
    assert row['features']['response_fraction'] == 0


def test_invalid_features_and_bounded_source_state(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(replace(config, max_sources=2))
    engine.fit_reference(rows)
    for i in range(5):
        engine.score({**rows[0], 'source': str(i)})
    assert len(engine.states) == 2 and engine.evictions == 3
    broken = {**rows[0], 'features': {**rows[0]['features'], 'packets': float('nan')}}
    with pytest.raises(ValueError):
        engine.score(broken)


def test_detector_replay_clones_keep_reference_but_not_temporal_state(reference):
    config, rows = reference
    detector = Detector()
    detector.fusion_engine = EvidenceFusionEngine(config)
    detector.fusion_engine.fit_reference(rows)
    detector.fusion_engine.score(fixture_row(np.random.default_rng(1), 10000, 'SYN_FLOOD'))
    clone = clone_isolated_detector(detector)
    assert not clone.fusion_engine.states
    assert clone.fusion_engine.reference_digest == detector.fusion_engine.reference_digest
    assert clone.anomaly_detector is not detector.anomaly_detector


def test_unknown_fusion_findings_reach_detector_decision(reference):
    config, rows = reference
    detector = Detector()
    detector.fusion_engine = EvidenceFusionEngine(config)
    detector.fusion_engine.fit_reference(rows)
    rng = np.random.default_rng(10)
    for t in range(10000, 10040, 5):
        result = detector.predict(fixture_row(rng, t, 'SLOW_SHIFT'))
    assert result['research_fusion']['is_anomalous']
    assert result['prediction'] == 'ANOMALOUS_UNKNOWN_PATTERN'
    assert result['decision'] in ('SUSPECTED', 'UNCERTAIN')


def test_constant_reference_still_detects_departures(reference):
    config, rows = reference
    engine = EvidenceFusionEngine(config)
    engine.fit_reference([rows[0]] * 48)
    unusual = {**rows[0], 'timestamp': 10000,
               'features': {**rows[0]['features'], 'packets': 10000}}
    result = engine.score(unusual)
    assert result['multivariate_distance'] > 0
    assert result['instant_candidate']
