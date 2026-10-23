import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from backend.api.app import create_app
from backend.api.capture_manager import CaptureManager
from backend.api.routes import set_capture_manager


class TestLensApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_path = Path("tests/fixtures/lens_api_sample.pcap")
        cls.fixture_path.parent.mkdir(parents=True, exist_ok=True)
        pkt = Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=8080, dport=80, flags="S")
        wrpcap(str(cls.fixture_path), [pkt])

        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.manager = CaptureManager()
        set_capture_manager(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop_capture()
        if cls.fixture_path.exists():
            cls.fixture_path.unlink()

    def test_lineage_verify_endpoint(self):
        resp = self.client.get("/api/lens/lineage/verify")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("is_valid", data)
        self.assertIn("events_count", data)

    def test_lineage_events_list_endpoint(self):
        resp = self.client.get("/api/lens/lineage/events?limit=10&offset=0")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("events", data)
        self.assertIn("total", data)

    def test_create_robustness_sweep_valid(self):
        payload = {
            "pcap_path": str(self.fixture_path),
            "loss_modes": ["random"],
            "drop_rates": [0.10],
            "seeds": [42],
            "max_runs": 1,
        }
        resp = self.client.post("/api/lens/robustness-runs", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("run_id", data)
        self.assertIn(data["status"], ["queued", "running", "completed"])

    def test_create_robustness_sweep_traversal_forbidden(self):
        payload = {
            "pcap_path": "../../../windows/system32/cmd.exe",
            "loss_modes": ["random"],
        }
        resp = self.client.post("/api/lens/robustness-runs", json=payload)
        self.assertEqual(resp.status_code, 403)

    def test_evidence_bundle_endpoint(self):
        # Create an event in lineage to bundle
        evt = self.manager.lineage_service.record_event("TEST_BUNDLE_EVENT", {"sample": 123})
        resp = self.client.get(f"/api/lens/evidence-bundle/{evt['event_id']}")
        self.assertEqual(resp.status_code, 200)
        bundle = resp.json()
        self.assertEqual(bundle["bundle_version"], "netguard-bundle-v1")
        self.assertIn("reproducibility_contract", bundle)
        self.assertIn("lineage_verification", bundle)


if __name__ == "__main__":
    unittest.main()
