import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap
from backend.analyzer.packet_parser import parse_packet
from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.ml.features import FeatureExtractor, FEATURES
from backend.ml.replay import replay
from backend.ml.train import load_manifest
from backend.ml.detector import Detector
from backend.ml.stream import StreamingAnalyzer


def packet(t, sport=5000, dport=443, flags='S', response=False):
    p = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP(
        src='10.0.0.2' if response else '10.0.0.1', dst='10.0.0.1' if response else '10.0.0.2')/TCP(sport=sport, dport=dport, flags=flags)
    p.time = t
    return p


class FeatureTests(unittest.TestCase):
    def test_window_expiry_and_future_exclusion(self):
        extractor = FeatureExtractor()
        self.assertEqual(extractor.process(parse_packet(packet(100))), [])
        rows = extractor.process(parse_packet(packet(101, dport=80)))
        self.assertEqual(rows[0]['features']['unique_ports'], 1)
        self.assertEqual(rows[0]['features']['packets'], 1)
        extractor.advance(107)
        self.assertEqual(extractor.advance(107), [])  # no duplicate tick
        self.assertFalse(extractor.sources)

    def test_bidirectional_handshake(self):
        ex = FeatureExtractor()
        for p in [packet(100), packet(100.1, 443, 5000, 'SA', True), packet(100.2, flags='A')]:
            ex.process(parse_packet(p))
        row = ex.advance(101)[0]
        self.assertEqual(row['features']['completed_fraction'], 1)
        self.assertAlmostEqual(row['features']['response_fraction'], 1/3)
        self.assertEqual(row['source'], '10.0.0.1')

    def test_bounds_and_out_of_order(self):
        ex = FeatureExtractor(max_sources=1, max_events=2, max_flows=2)
        for i in range(5):
            ex.process(parse_packet(packet(100+i*.01, sport=5000+i)))
        self.assertEqual(len(ex.flows), 2)
        self.assertEqual(len(next(iter(ex.sources.values()))), 2)
        self.assertGreater(ex.evictions, 0)
        ex.process(parse_packet(packet(99)))
        self.assertEqual(ex.late_packets, 1)
        ex.process(replace(parse_packet(packet(100.1)), source_ip='10.1.1.1'))
        self.assertEqual(len(ex.sources), 1)

    def test_replay_identical_to_direct(self):
        packets = [packet(100+i*.2, dport=20+i) for i in range(20)]
        ex = FeatureExtractor()
        expected = []
        for p in packets:
            expected.extend(ex.process(parse_packet(p)))
        expected.extend(ex.finish())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'test.pcap'
            wrpcap(str(path), packets)
            self.assertEqual(list(replay(path)), expected)
            self.assertEqual(list(replay(path, .3)), list(replay(path, .3)))

    def test_manifest_rejects_reused_capture(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'manifest.json'
            path.write_text(json.dumps([{'session': str(i), 'pcap': 'same.pcap', 'split': split, 'label': 'BENIGN'}
                                        for i, split in enumerate(('train', 'validation', 'test'))]))
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_trained_model_and_stream_drain(self):
        # Uses the explicitly generated local demo artifact; skip in clean checkouts.
        path = Path('artifacts/netguard.joblib')
        if not path.exists():
            self.skipTest('Run documented demo training to exercise trained inference')
        with tempfile.TemporaryDirectory() as d:
            output = Path(d)/'predictions.jsonl'
            stream = StreamingAnalyzer(TrafficAnalyzer(), path, output, offline=True, queue_size=2)
            for i in range(100):
                stream.process(parse_packet(packet(100+i*.03, dport=20+i)))
            stream.close()
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertGreater(len(records), 0)
            self.assertEqual(stream.snapshot()['ml']['queue_drops'], 0)
            self.assertIn('PORT_SCAN', {r['prediction'] for r in records})
            self.assertTrue(all(r['model_scope'] == 'synthetic-demo' for r in records))
            self.assertTrue(all(set(r['features']) == set(FEATURES) for r in records))

    def test_state_loss_marks_suspicious_prediction_uncertain(self):
        path = Path('artifacts/netguard.joblib')
        if not path.exists():
            self.skipTest('Run demo training first')
        ex = FeatureExtractor()
        for i in range(60):
            ex.process(parse_packet(packet(100+i*.01, dport=20+i)))
        row = ex.finish()[0]
        row['quality']['state_evictions'] = 1
        result = Detector(path).predict(row)
        self.assertNotEqual(result['prediction'], 'BENIGN')
        self.assertEqual(result['decision'], 'UNCERTAIN')
