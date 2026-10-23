import tempfile
import unittest
from pathlib import Path
from backend.storage.repository import IncidentRepository, pseudonymize_ip


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_incidents.db"
        self.repo = IncidentRepository(str(self.db_path))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pseudonymize_ip(self):
        self.assertEqual(pseudonymize_ip("192.168.1.10"), "192.168.1.xxx")
        self.assertEqual(pseudonymize_ip("10.0.2.15"), "10.0.2.xxx")
        self.assertEqual(pseudonymize_ip(None), "-")

    def test_save_and_retrieve_incident(self):
        inc = {
            "source_ip": "10.0.2.1",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "detector_class": "PORT_SCAN",
            "detector_score": 0.985,
            "decision": "SUSPECTED",
            "evidence": {"unique_ports": 45, "syn_rate": 12.0},
            "capture_quality": {"overall_status": "HEALTHY"}
        }
        alert_id = self.repo.save_incident(inc)
        self.assertIsNotNone(alert_id)

        retrieved = self.repo.get_incident_by_id(alert_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["detector_class"], "PORT_SCAN")
        self.assertEqual(retrieved["source_ip"], "10.0.2.1")
        self.assertIn("Flagged as PORT_SCAN", retrieved["why_flagged"])

        # Test with IP pseudonymization
        redacted = self.repo.get_incident_by_id(alert_id, redact_ips=True)
        self.assertEqual(redacted["source_ip"], "10.0.2.xxx")

    def test_pagination_and_export(self):
        for i in range(5):
            self.repo.save_incident({
                "source_ip": f"10.0.0.{i+1}",
                "destination_ip": "192.168.1.1",
                "protocol": "TCP",
                "detector_class": "SYN_FLOOD" if i % 2 == 0 else "BENIGN",
                "decision": "SUSPECTED" if i % 2 == 0 else "BENIGN"
            })

        items, total = self.repo.get_incidents(limit=2, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(items), 2)

        # Filter by class
        syn_items, syn_total = self.repo.get_incidents(class_filter="SYN_FLOOD")
        self.assertEqual(syn_total, 3)

        # Export JSON
        json_export = self.repo.export_json(redact_ips=True)
        self.assertIn("netguard-evidence-passport-v1", json_export)
        self.assertIn("10.0.0.xxx", json_export)

        # Export CSV
        csv_export = self.repo.export_csv()
        self.assertIn("alert_id,iso_time,source_ip", csv_export)
