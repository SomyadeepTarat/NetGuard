import time
import unittest
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

from backend.ml.detector import Detector
from backend.ml.robustness_sweep import RobustnessSweepEngine
from backend.services.pcap_resolver import compute_pcap_fingerprint, verify_pcap_unmodified


class TestRobustnessSweep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_path = Path("tests/fixtures/sweep_test_sample.pcap")
        cls.fixture_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate a small stream of packets: SYN flood pattern
        pkts = []
        base_t = 1700000000.0
        for i in range(50):
            p = (
                Ether()
                / IP(src="192.168.1.105", dst="192.168.1.1")
                / TCP(sport=10000 + i, dport=80, flags="S")
            )
            p.time = base_t + (i * 0.05)
            pkts.append(p)

        wrpcap(str(cls.fixture_path), pkts)
        cls.initial_sha256, _ = compute_pcap_fingerprint(cls.fixture_path)

    @classmethod
    def tearDownClass(cls):
        if cls.fixture_path.exists():
            cls.fixture_path.unlink()

    def setUp(self):
        self.detector = Detector()
        self.engine = RobustnessSweepEngine(detector=self.detector)

    def test_matrix_builder_bounds_and_modes(self):
        matrix = self.engine.build_default_scenario_matrix(
            loss_modes=["random", "burst"],
            drop_rates=[0.10, 0.20],
            seeds=[11, 23],
            max_runs=10
        )
        self.assertLessEqual(len(matrix), 10)
        modes = set(sc.loss_mode for sc in matrix)
        self.assertTrue(modes.issubset({"random", "burst"}))
        for sc in matrix:
            self.assertIn(sc.seed, [11, 23])

    def test_sweep_execution_packet_accounting_and_non_mutation(self):
        run = self.engine.create_sweep_run(
            pcap_path=str(self.fixture_path),
            loss_modes=["random"],
            drop_rates=[0.20],
            seeds=[42],
            max_runs=1
        )

        # Wait for completion (bounded, should take < 3 seconds)
        for _ in range(50):
            if run.status in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.1)

        self.assertEqual(run.status, "completed")
        self.assertEqual(run.completed_scenarios, 1)
        self.assertTrue(verify_pcap_unmodified(self.fixture_path, self.initial_sha256))

        # Check scenario results
        self.assertEqual(len(run.scenario_results), 1)
        sc = run.scenario_results[0]
        self.assertEqual(sc["status"], "completed")
        self.assertEqual(sc["source_packets"], 50)
        self.assertEqual(sc["omitted_packets"] + sc["retained_packets"], 50)
        self.assertGreaterEqual(sc["window_alignment_coverage"], 0.0)
        self.assertIn(run.stability_verdict, ["STABLE", "SENSITIVE", "INCONCLUSIVE"])

    def test_sweep_cancellation(self):
        run = self.engine.create_sweep_run(
            pcap_path=str(self.fixture_path),
            loss_modes=["random", "burst"],
            drop_rates=[0.05, 0.10, 0.20, 0.30],
            seeds=[11, 23, 37],
            max_runs=20
        )
        # Immediately request cancellation
        cancelled = self.engine.cancel_sweep_run(run.run_id)
        self.assertTrue(cancelled)


if __name__ == "__main__":
    unittest.main()
