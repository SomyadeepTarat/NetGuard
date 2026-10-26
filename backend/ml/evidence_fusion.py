"""Experimental observation-aware graph / conformal / sequential detector.

Known algorithms are composed here; this module does not claim a new statistical
theorem. References, assumptions and the ablation protocol are in
docs/evidence_fusion.md. All state is session-local and bounded.
"""
from collections import OrderedDict
from dataclasses import asdict, dataclass
from copy import deepcopy
import hashlib
import json
import math

import numpy as np
from sklearn.covariance import LedoitWolf

from backend.ml.features import FEATURES


@dataclass(frozen=True)
class FusionConfig:
    fit_windows: int = 32
    calibration_windows: int = 64
    alpha: float = 0.05
    cusum_allowance: float = 1.5
    cusum_threshold: float = 8.0
    interval_seconds: float = 5.0
    max_sources: int = 256
    graph_enabled: bool = True
    temporal_enabled: bool = True
    visibility_enabled: bool = True

    def __post_init__(self):
        if self.fit_windows < 8 or self.calibration_windows < 20:
            raise ValueError('Reference requires >=8 fit and >=20 calibration windows')
        if not 1 / (self.calibration_windows + 1) <= self.alpha < 0.5:
            raise ValueError('alpha must be resolvable by calibration size and below 0.5')
        if min(self.cusum_allowance, self.cusum_threshold, self.interval_seconds, self.max_sources) <= 0:
            raise ValueError('Sequential parameters and state limits must be positive')


class EvidenceFusionEngine:
    version = 'observation-aware-fusion-v1'

    def __init__(self, config=None):
        self.config = config or FusionConfig()
        self.reference = []
        self.model = None
        self.states = OrderedDict()
        self.reference_scope = 'automatic-rule-screened-unverified'
        self.rejected_reference_windows = 0
        self.evictions = 0
        self.evaluated = 0
        self.last_result = None

    @staticmethod
    def vector(row):
        values = np.asarray([float(row['features'].get(f, 0)) for f in FEATURES])
        if not np.isfinite(values).all() or (values < 0).any():
            raise ValueError('Fusion features must be finite and nonnegative')
        return np.log1p(values)

    def _state(self, source):
        if source not in self.states:
            if len(self.states) >= self.config.max_sources:
                self.states.popitem(last=False)
                self.evictions += 1
            self.states[source] = {'last_reference': -math.inf, 'last_tick': -math.inf,
                                   'sum': 0.0, 'ticks': 0}
        self.states.move_to_end(source)
        return self.states[source]

    @staticmethod
    def _edges(row):
        context = row.get('graph_context', {})
        return set(context.get('edges', []))

    def _graph_score(self, row):
        if not self.config.graph_enabled or not row.get('graph_context'):
            return 0.0
        peers = float(row['graph_context'].get('out_degree', 0))
        if not math.isfinite(peers) or peers < 0:
            raise ValueError('Observed graph degree must be finite and nonnegative')
        edges = self._edges(row)
        known = self.known_edges.get(row.get('source'))
        novelty = len(edges - known) / max(len(edges), 1) if known else 0.0
        # A star with many peers and new peer/service edges is stronger than
        # one newly observed connection. New sources have no novelty prior.
        return math.log1p(peers) * (1.0 + novelty)

    def _raw_scores(self, row, neutralize_visibility=False):
        x = self.vector(row)
        if neutralize_visibility:
            x = x.copy()
            for name in ('response_fraction', 'completed_fraction', 'rst_fraction'):
                i = FEATURES.index(name)
                x[i] = self.center[i]
        z = (x - self.center) / self.scale
        distance = float(max(0.0, self.model.mahalanobis([z])[0])) / len(FEATURES)
        graph = self._graph_score(row)
        return distance, graph

    @staticmethod
    def _tail(scores, value):
        return (1 + int(np.count_nonzero(scores >= value))) / (len(scores) + 1)

    def fit_reference(self, rows, scope='analyst-supplied-benign'):
        """Disjoint chronological fit/calibration blocks, frozen after fitting.

        Caller must supply benign independent sessions for a defensible reference.
        Automatic warm-up cannot establish benign ground truth.
        """
        needed = self.config.fit_windows + self.config.calibration_windows
        if len(rows) < needed:
            raise ValueError(f'Reference needs at least {needed} windows')
        self.reference = deepcopy(list(rows[:needed]))
        fit = self.reference[:self.config.fit_windows]
        calibration = self.reference[self.config.fit_windows:]
        X = np.asarray([self.vector(row) for row in fit])
        self.center = np.median(X, axis=0)
        self.scale = np.maximum(np.median(np.abs(X - self.center), axis=0) * 1.4826, 0.05)
        self.model = LedoitWolf().fit((X - self.center) / self.scale)
        # A completely constant fit block otherwise has zero covariance and
        # zero pseudo-precision, assigning zero distance to every future row.
        self.model.covariance_ = self.model.covariance_ + np.eye(len(FEATURES)) * 1e-3
        self.model.precision_ = np.linalg.pinv(self.model.covariance_, hermitian=True)
        self.known_edges = {}
        for row in fit:
            self.known_edges.setdefault(row.get('source'), set()).update(self._edges(row))
        scores = np.asarray([self._raw_scores(row) for row in calibration])
        self.feature_scores = scores[:, 0]
        self.graph_scores = scores[:, 1]
        # Combine raw nonconformities BEFORE calibration; no independence
        # assumption between graph and multivariate feature views is needed.
        fit_scores = np.asarray([self._raw_scores(row) for row in fit])
        self.graph_weight = max(float(np.median(fit_scores[:, 0])), 0.1) / max(float(np.median(fit_scores[:, 1])), 1.0)
        self.joint_scores = np.maximum(self.feature_scores, self.graph_scores * self.graph_weight)
        self.reference_scope = scope
        identity = {'config': asdict(self.config), 'scope': scope, 'rows': self.reference}
        self.reference_digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.states.clear()

    def score(self, row, allow_reference=False):
        # Missing source/timestamp is common in old rule-only API callers.
        if 'source' not in row or 'timestamp' not in row:
            return {'status': 'UNAVAILABLE', 'reason': 'Source and timestamp required', 'is_anomalous': False}
        self.vector(row)
        t = float(row['timestamp'])
        if not math.isfinite(t):
            raise ValueError('Fusion timestamp must be finite')
        state = self._state(row['source'])
        if self.model is None:
            if allow_reference and t - state['last_reference'] >= self.config.interval_seconds:
                self.reference.append(row)
                state['last_reference'] = t
                if len(self.reference) >= self.config.fit_windows + self.config.calibration_windows:
                    self.fit_reference(self.reference, self.reference_scope)
            elif not allow_reference:
                self.rejected_reference_windows += 1
            result = {'status': 'WARM_UP', 'is_anomalous': False,
                      'reference_windows': len(self.reference),
                      'reference_target': self.config.fit_windows + self.config.calibration_windows,
                      'reference_scope': self.reference_scope}
            self.last_result = result
            return result

        state = self._state(row['source'])
        distance, graph = self._raw_scores(row)
        joint = max(distance, graph * self.graph_weight)
        p = self._tail(self.joint_scores, joint)
        instant = p <= self.config.alpha
        updated = t - state['last_tick'] >= self.config.interval_seconds
        if updated:
            # Do not carry evidence indefinitely across idle periods.
            if t - state['last_tick'] > 60:
                state['sum'], state['ticks'] = 0.0, 0
            state['sum'] = min(100.0, max(0.0, state['sum'] - math.log(p) - self.config.cusum_allowance))
            state['ticks'] += 1
            state['last_tick'] = t
        confirmed = instant and (not self.config.temporal_enabled or (
            state['sum'] >= self.config.cusum_threshold and state['ticks'] >= 2))
        visibility = {'status': 'DISABLED', 'masked_p_value': None}
        if self.config.visibility_enabled:
            masked_distance, masked_graph = self._raw_scores(row, neutralize_visibility=True)
            masked_p = self._tail(self.joint_scores, max(masked_distance, masked_graph * self.graph_weight))
            visibility = {'status': 'SENSITIVE' if instant and masked_p > self.config.alpha else 'UNCHANGED_IN_TESTED_MASK',
                          'masked_p_value': round(masked_p, 6),
                          'intervention': 'Set response/completion/reset log-features to fit-reference medians; not reconstructed packets'}
        z = np.abs((self.vector(row) - self.center) / self.scale)
        top = np.argsort(-z)[:3]
        result = {'status': 'READY', 'version': self.version, 'is_anomalous': bool(confirmed),
                  'instant_candidate': bool(instant), 'p_value': round(p, 6),
                  'feature_p_value': round(self._tail(self.feature_scores, distance), 6),
                  'graph_p_value': round(self._tail(self.graph_scores, graph), 6),
                  'multivariate_distance': round(distance, 6), 'graph_score': round(graph, 6),
                  'graph_available': bool(row.get('graph_context')) and self.config.graph_enabled,
                  'temporal_evidence': round(state['sum'], 6), 'temporal_threshold': self.config.cusum_threshold,
                  'temporal_updated': updated, 'visibility': visibility,
                  'top_deviations': [{'feature': FEATURES[i], 'robust_deviation': round(float(z[i]), 4)} for i in top],
                  'reference_scope': self.reference_scope, 'reference_sha256': self.reference_digest,
                  'statistical_note': 'Empirical split-conformal rank; overlapping, dependent or shifted traffic does not establish guaranteed false-alarm control. CUSUM is heuristic, not an anytime-valid test.'}
        self.evaluated += 1
        self.last_result = result
        return result

    def status(self):
        return {'version': self.version, 'ready': self.model is not None, 'config': asdict(self.config),
                'reference_windows': len(self.reference), 'reference_scope': self.reference_scope,
                'reference_sha256': getattr(self, 'reference_digest', None),
                'rejected_reference_windows': self.rejected_reference_windows,
                'state_evictions': self.evictions, 'evaluated_windows': self.evaluated,
                'last_result': self.last_result}

    def fresh(self):
        """Share only the frozen reference; never temporal/source state."""
        engine = EvidenceFusionEngine(self.config)
        if self.model is not None:
            engine.fit_reference(self.reference, self.reference_scope)
        return engine
