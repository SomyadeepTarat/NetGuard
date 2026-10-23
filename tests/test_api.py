import unittest
from fastapi.testclient import TestClient
from backend.api.app import create_app
from backend.api.capture_manager import CaptureManager
from backend.api.routes import set_capture_manager


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)
        # Manually ensure capture manager is wired for test client
        cls.manager = CaptureManager()
        set_capture_manager(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop_capture()

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("mode", data)
        self.assertIn("capture_quality_status", data)

    def test_overview_endpoint(self):
        resp = self.client.get("/api/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_packets", data)
        self.assertIn("protocols", data)
        self.assertIn("capture_quality", data)

    def test_timeseries_endpoint(self):
        resp = self.client.get("/api/traffic/timeseries")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_interfaces_endpoint(self):
        resp = self.client.get("/api/interfaces")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_flows_and_hosts(self):
        resp_flows = self.client.get("/api/flows?limit=10")
        self.assertEqual(resp_flows.status_code, 200)
        self.assertIn("flows", resp_flows.json())

        resp_hosts = self.client.get("/api/hosts")
        self.assertEqual(resp_hosts.status_code, 200)
        data = resp_hosts.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("disclaimer", data)

    def test_alerts_and_exports(self):
        resp_alerts = self.client.get("/api/alerts")
        self.assertEqual(resp_alerts.status_code, 200)
        self.assertIn("alerts", resp_alerts.json())

        resp_json = self.client.get("/api/alerts/export/json?redact_ips=true")
        self.assertEqual(resp_json.status_code, 200)
        self.assertIn("netguard-evidence-passport-v1", resp_json.text)

        resp_csv = self.client.get("/api/alerts/export/csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("alert_id", resp_csv.text)

    def test_replays_pcaps_and_settings(self):
        resp_pcaps = self.client.get("/api/replays/pcaps")
        self.assertEqual(resp_pcaps.status_code, 200)

        resp_settings = self.client.get("/api/settings")
        self.assertEqual(resp_settings.status_code, 200)
        self.assertEqual(resp_settings.json()["host_binding"], "127.0.0.1")

    def test_evaluation_endpoint(self):
        resp = self.client.get("/api/evaluation")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(resp.json()["status"], ("EVALUATED", "NOT_EVALUATED"))
