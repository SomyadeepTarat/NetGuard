import copy
import unittest
import numpy as np
from backend.analyzer.packet_parser import parse_packet
from backend.ml.features import FeatureExtractor, FEATURES
from backend.ml.fragility import handshake_fragility
from backend.ml.detector import Detector
from test_ml import packet


class ScenarioModel:
    classes_ = np.array(['BENIGN', 'SYN_FLOOD'])

    def predict_proba(self, rows):
        self.rows = rows
        # Deliberately nonmonotonic: only a single completed flow flips.
        return np.array([[.95, .05] if abs(r[FEATURES.index('completed_fraction')] - .5) < 1e-9
                         else [.01, .99] for r in rows])


def extract(packets):
    ex = FeatureExtractor()
    for p in packets:
        ex.process(parse_packet(p))
    return ex.advance(101)[0]


class FragilityTests(unittest.TestCase):
    def row(self):
        return extract([packet(100), packet(100.1, sport=5001), packet(100.8, flags='')])

    def test_scenario_matches_reextraction_and_preserves_evidence(self):
        row = self.row()
        before = copy.deepcopy(row)
        model = ScenarioModel()
        result = handshake_fragility(model, row, .9)
        actual = extract([packet(100), packet(100.1, sport=5001),
                          packet(100.2, 443, 5000, 'SA', True),
                          packet(100.3, flags='A'), packet(100.8, flags='')])
        for name, value in zip(FEATURES, model.rows[0]):
            self.assertAlmostEqual(value, actual['features'][name], msg=name)
        self.assertEqual(row, before)
        self.assertEqual(result['minimum_tested_pairs_to_change'], 1)
        self.assertEqual(result['tested_scenarios'], 2)
        self.assertAlmostEqual(result['hypothetical_missing_fraction'], 2 / 5)
        self.assertEqual(result['alternative_prediction'], 'BENIGN')

    def test_excludes_replies_resets_completed_and_last_timestamp(self):
        row = extract([packet(100), packet(100.1, 443, 5000, 'SA', True),
                       packet(100.2, flags='A'), packet(100.3, sport=5001),
                       packet(100.4, sport=5001, flags='R'), packet(100.8, sport=5002)])
        self.assertEqual(row['handshake_context']['repairable_flows'], 0)
        self.assertEqual(handshake_fragility(ScenarioModel(), row, .9)['status'], 'unavailable')

    def test_unknown_and_recorded_loss(self):
        row = self.row()
        for key in ('late_packets', 'state_evictions', 'queue_drops'):
            damaged = copy.deepcopy(row)
            damaged['quality'][key] = 1
            self.assertEqual(handshake_fragility(ScenarioModel(), damaged, .9)['status'], 'unavailable')
        del row['handshake_context']
        self.assertEqual(handshake_fragility(ScenarioModel(), row, .9)['status'], 'unavailable')

    def test_search_cap_and_no_claim_of_robustness(self):
        row = extract([packet(100 + i * .01, sport=5000+i) for i in range(60)])
        result = handshake_fragility(ScenarioModel(), row, .9, max_pairs=4)
        self.assertEqual(result['status'], 'unchanged_in_tested_scenarios')
        self.assertEqual(result['tested_scenarios'], 4)
        self.assertTrue(result['search_truncated'])
        self.assertIsNone(result['minimum_tested_pairs_to_change'])

    def test_detector_keeps_original_alert_decision(self):
        detector = Detector.__new__(Detector)
        detector.bundle = {'model': ScenarioModel(), 'scope': 'test'}
        detector.threshold = .9
        result = detector.predict(self.row())
        self.assertEqual(result['fragility']['status'], 'sensitive')
        self.assertEqual(result['prediction'], 'SYN_FLOOD')
        self.assertEqual(result['decision'], 'SUSPECTED')
