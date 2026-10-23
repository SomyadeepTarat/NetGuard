import time
import unittest
from pathlib import Path
from backend.ml.detector import Detector
from backend.services.replay_lab import ReplayLabService


class ReplayLabTests(unittest.TestCase):
    def setUp(self):
        # Use existing trained demo model if available, else rule-fallback detector
        model_path = Path("artifacts/netguard.joblib")
        self.detector = Detector(str(model_path) if model_path.exists() else None)
        self.service = ReplayLabService(self.detector)

    def test_list_available_pcaps(self):
        pcaps = self.service.list_available_pcaps()
        self.assertIsInstance(pcaps, list)
        if pcaps:
            self.assertTrue(all("filename" in p for p in pcaps))

    def test_run_replay_experiment_deterministic(self):
        # Look for a demo PCAP
        demo_pcaps = list(Path("artifacts/demo").glob("*.pcap")) if Path("artifacts/demo").exists() else []
        if not demo_pcaps:
            self.skipTest("No demo PCAPs generated yet.")

        pcap = str(demo_pcaps[0])
        exp = self.service.create_experiment(
            pcap_path=pcap,
            loss_mode="random",
            drop_rate=0.2,
            seed=42
        )
        self.assertIsNotNone(exp.run_id)

        # Wait for experiment completion
        for _ in range(50):
            res = self.service.get_experiment(exp.run_id)
            if res and res["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)

        completed = self.service.get_experiment(exp.run_id)
        self.assertEqual(completed["status"], "completed")
        self.assertIn("baseline_summary", completed)
        self.assertIn("perturbed_summary", completed)
        self.assertIn(completed["stability_verdict"], ("STABLE", "SENSITIVE", "INCONCLUSIVE"))
        self.assertIn("OFFLINE SIMULATION", completed["advisory_disclaimer"])
