import tempfile
import time
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from backend.api.app import create_app
from backend.api.capture_manager import CaptureManager
from backend.api.routes import set_capture_manager
from backend.services.pcap_resolver import compute_pcap_fingerprint, verify_pcap_unmodified


class TestNextObservationWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = str(Path(cls.temp_dir.name) / "test_workflow_incidents.db")

        # 1. Create SYN flood fixture with sufficient frames
        cls.syn_fixture = Path("tests/fixtures/workflow_syn_flood.pcap")
        cls.syn_fixture.parent.mkdir(parents=True, exist_ok=True)
        pkts = []
        base_t = 1700000000.0
        for i in range(50):
            p = Ether() / IP(src="192.168.1.105", dst="192.168.1.1") / TCP(sport=10000 + i, dport=80, flags="S")
            p.time = base_t + (i * 0.05)
            pkts.append(p)
        wrpcap(str(cls.syn_fixture), pkts)
        cls.initial_syn_sha, _ = compute_pcap_fingerprint(cls.syn_fixture)

        # 2. Use canonical benign demo fixture
        demo_benign = Path("artifacts/demo/test-BENIGN-0.pcap")
        if demo_benign.exists():
            cls.benign_fixture = demo_benign
        else:
            cls.benign_fixture = Path("tests/fixtures/workflow_benign.pcap")
            # Create bidirectional completed TCP connection
            pkts_benign = [
                Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / TCP(sport=20000, dport=80, flags="S"),
                Ether() / IP(src="192.168.1.1", dst="192.168.1.20") / TCP(sport=80, dport=20000, flags="SA"),
                Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / TCP(sport=20000, dport=80, flags="A"),
                Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / TCP(sport=20000, dport=80, flags="PA"),
                Ether() / IP(src="192.168.1.1", dst="192.168.1.20") / TCP(sport=80, dport=20000, flags="A"),
            ]
            wrpcap(str(cls.benign_fixture), pkts_benign)
        cls.initial_benign_sha, _ = compute_pcap_fingerprint(cls.benign_fixture)

        # 3. Setup FastAPI app & manager with isolated test database
        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.manager = CaptureManager(db_path=cls.db_path)
        set_capture_manager(cls.manager)

    @classmethod
    def tearDownClass(cls):
        cls.manager.stop_capture()
        cls.temp_dir.cleanup()
        if cls.syn_fixture.exists():
            cls.syn_fixture.unlink()
        if cls.benign_fixture.name == "workflow_benign.pcap" and cls.benign_fixture.exists():
            cls.benign_fixture.unlink()

    def test_01_completed_sweep_appears_in_next_observation_selector(self):
        """1. A completed sweep appears in the Next Observation selector."""
        # Queue and run a 2-scenario sweep
        payload = {
            "pcap_path": str(self.syn_fixture),
            "loss_modes": ["random", "directional"],
            "drop_rates": [0.20],
            "seeds": [42],
            "max_runs": 2,
        }
        resp = self.client.post("/api/lens/robustness-runs", json=payload)
        self.assertEqual(resp.status_code, 200)
        run_data = resp.json()
        run_id = run_data["run_id"]

        # Wait for completion (bounded max 10 seconds)
        for _ in range(50):
            poll = self.client.get(f"/api/lens/robustness-runs/{run_id}")
            self.assertEqual(poll.status_code, 200)
            if poll.json()["status"] == "completed":
                break
            time.sleep(0.1)

        poll = self.client.get(f"/api/lens/robustness-runs/{run_id}")
        self.assertEqual(poll.json()["status"], "completed")

        # Verify it is returned in the authoritative list used by NextObservationTab
        sweeps_resp = self.client.get("/api/lens/robustness-runs")
        self.assertEqual(sweeps_resp.status_code, 200)
        sweeps_list = sweeps_resp.json()
        self.assertGreaterEqual(len(sweeps_list), 1)
        found = next((s for s in sweeps_list if s["run_id"] == run_id), None)
        self.assertIsNotNone(found)
        self.assertEqual(found["pcap_name"], self.syn_fixture.name)

        # Save run_id for subsequent tests
        TestNextObservationWorkflow.completed_sweep_id = run_id

    def test_02_sweep_only_planning_works_with_empty_repository(self):
        """2. Sweep-only planning works with an empty incident repository when sufficient evidence exists."""
        run_id = getattr(self, "completed_sweep_id", None)
        self.assertIsNotNone(run_id, "Completed sweep ID missing from previous step")

        # Verify repository currently has 0 incidents
        incidents, total = self.manager.repository.get_incidents()
        self.assertEqual(total, 0, "Repository should have zero incidents at this point")

        # Test direct sweep route: /api/lens/sweeps/{run_id}/observation-plan
        resp = self.client.get(f"/api/lens/sweeps/{run_id}/observation-plan")
        self.assertEqual(resp.status_code, 200)
        plan = resp.json()

        self.assertEqual(plan["plan_mode"], "SWEEP_ONLY_ADVISORY")
        self.assertIsNone(plan["target_alert_id"])
        self.assertEqual(plan["target_sweep_id"], run_id)
        self.assertFalse(plan["active_network_action"])
        self.assertIn("SWEEP-ONLY ADVISORY PLAN — NO EVIDENCE PASSPORT LINKED", plan["disclaimer"])
        self.assertIn(plan["status"], ["READY", "NO_GAPS_IDENTIFIED"])

        # Also test unified route: /api/lens/observation-plan?run_id=...
        unified_resp = self.client.get(f"/api/lens/observation-plan?run_id={run_id}")
        self.assertEqual(unified_resp.status_code, 200)
        unified_plan = unified_resp.json()
        self.assertEqual(unified_plan["plan_mode"], "SWEEP_ONLY_ADVISORY")
        self.assertEqual(unified_plan["target_sweep_id"], run_id)

    def test_03_incident_linked_planning_works_when_genuine_passport_exists(self):
        """3. Incident-linked planning works when a genuine Evidence Passport exists."""
        # Ingest genuine threat incident via safe offline PCAP analysis
        analyze_resp = self.client.post("/api/alerts/analyze-pcap", json={"pcap_path": str(self.syn_fixture)})
        self.assertEqual(analyze_resp.status_code, 200)
        analyze_data = analyze_resp.json()
        self.assertEqual(analyze_data["status"], "completed")
        self.assertGreaterEqual(analyze_data["incidents_recorded"], 1)

        # Retrieve the newly created alert
        alert = analyze_data["alerts"][0]
        alert_id = alert["alert_id"]
        TestNextObservationWorkflow.created_alert_id = alert_id

        # Mode A without sweep correlation
        resp_a1 = self.client.get(f"/api/lens/alerts/{alert_id}/observation-plan")
        self.assertEqual(resp_a1.status_code, 200)
        plan_a1 = resp_a1.json()
        self.assertEqual(plan_a1["plan_mode"], "INCIDENT_LINKED")
        self.assertEqual(plan_a1["target_alert_id"], alert_id)
        self.assertIsNone(plan_a1["target_sweep_id"])
        self.assertFalse(plan_a1["active_network_action"])

        # Mode A with sweep correlation
        run_id = getattr(self, "completed_sweep_id", None)
        resp_a2 = self.client.get(f"/api/lens/alerts/{alert_id}/observation-plan?run_id={run_id}")
        self.assertEqual(resp_a2.status_code, 200)
        plan_a2 = resp_a2.json()
        self.assertEqual(plan_a2["plan_mode"], "INCIDENT_LINKED")
        self.assertEqual(plan_a2["target_alert_id"], alert_id)
        self.assertEqual(plan_a2["target_sweep_id"], run_id)
        self.assertFalse(plan_a2["active_network_action"])
        self.assertTrue(plan_a2["evidence_summary"]["is_incident_linked"])

    def test_04_insufficient_evidence_produces_explicit_honest_state(self):
        """4. Insufficient evidence produces an explicit, honest state."""
        # 1. No incident and no sweep provided
        resp_empty = self.client.get("/api/lens/observation-plan")
        self.assertEqual(resp_empty.status_code, 200)
        plan_empty = resp_empty.json()
        self.assertEqual(plan_empty["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(plan_empty["total_recommendations"], 0)
        self.assertIn("Neither Evidence Passport nor Robustness Sweep", plan_empty["insufficient_reason"])

        # 2. Non-existent alert produces 404
        resp_404 = self.client.get("/api/lens/alerts/non_existent_alert/observation-plan")
        self.assertEqual(resp_404.status_code, 404)

        # 3. Non-existent sweep produces 404
        resp_sweep_404 = self.client.get("/api/lens/sweeps/non_existent_sweep/observation-plan")
        self.assertEqual(resp_sweep_404.status_code, 404)

    def test_05_recommendations_contain_triggering_evidence_and_passive_status(self):
        """5. Recommendations include actual triggering evidence and passive-action status."""
        alert_id = getattr(self, "created_alert_id", None)
        run_id = getattr(self, "completed_sweep_id", None)
        resp = self.client.get(f"/api/lens/alerts/{alert_id}/observation-plan?run_id={run_id}")
        self.assertEqual(resp.status_code, 200)
        plan = resp.json()

        for rec in plan["recommendations"]:
            self.assertFalse(rec["active_network_action"], "active_network_action MUST be False")
            self.assertIn("rule_id", rec)
            self.assertIn("priority", rec)
            self.assertIn("score", rec)
            self.assertGreater(len(rec["trigger_evidence"]), 0)
            self.assertGreater(len(rec["what_to_observe_next"]), 0)
            self.assertGreater(len(rec["expected_clarification"]), 0)
            self.assertIn(rec["expected_effort"], ["LOW", "MEDIUM", "HIGH"])
            self.assertIn(rec["privacy_impact"], ["NONE", "LOW", "MEDIUM"])

    def test_06_evidence_passport_originates_from_actual_detector_output(self):
        """6. A newly created Evidence Passport originates from actual detector output (not merely SYN_FLOOD filename)."""
        # A. Analyze benign capture
        benign_resp = self.client.post("/api/alerts/analyze-pcap", json={"pcap_path": str(self.benign_fixture)})
        self.assertEqual(benign_resp.status_code, 200)
        benign_data = benign_resp.json()
        self.assertEqual(benign_data["incidents_recorded"], 0, "Benign traffic must NOT generate an incident")

        # B. Analyze SYN flood capture
        syn_resp = self.client.post("/api/alerts/analyze-pcap", json={"pcap_path": str(self.syn_fixture)})
        self.assertEqual(syn_resp.status_code, 200)
        syn_data = syn_resp.json()
        self.assertGreaterEqual(syn_data["incidents_recorded"], 1)

        alert = syn_data["alerts"][0]
        self.assertEqual(alert["detector_class"], "SYN_FLOOD")
        self.assertIn(alert["decision"], ["SUSPECTED", "UNCERTAIN"])
        self.assertIn("capture_quality", alert)
        self.assertIn("rule_triggers", alert)
        self.assertIn("offline-pcap", alert["provenance"])

    def test_07_atlas_lineage_and_original_incident_remain_unchanged_by_planning(self):
        """7. The Atlas, lineage event history, and original incident remain unchanged by planning."""
        alert_id = getattr(self, "created_alert_id", None)
        run_id = getattr(self, "completed_sweep_id", None)

        # Baseline snapshots before planning
        original_incident = self.manager.repository.get_incident_by_id(alert_id)
        original_sweep = self.manager.robustness_sweep.get_sweep_run(run_id)

        # Generate plans multiple times
        for _ in range(3):
            self.client.get(f"/api/lens/alerts/{alert_id}/observation-plan?run_id={run_id}")
            self.client.get(f"/api/lens/sweeps/{run_id}/observation-plan")

        # Verify incident has not mutated
        after_incident = self.manager.repository.get_incident_by_id(alert_id)
        self.assertEqual(original_incident["alert_id"], after_incident["alert_id"])
        self.assertEqual(original_incident["timestamp"], after_incident["timestamp"])
        self.assertEqual(original_incident["decision"], after_incident["decision"])
        self.assertEqual(original_incident["detector_class"], after_incident["detector_class"])

        # Verify sweep run has not mutated
        after_sweep = self.manager.robustness_sweep.get_sweep_run(run_id)
        self.assertEqual(original_sweep["stability_verdict"], after_sweep["stability_verdict"])
        self.assertEqual(original_sweep["completed_scenarios"], after_sweep["completed_scenarios"])

        # Verify PCAP files remain byte-exact
        self.assertTrue(verify_pcap_unmodified(self.syn_fixture, self.initial_syn_sha))
        self.assertTrue(verify_pcap_unmodified(self.benign_fixture, self.initial_benign_sha))

        # Verify lineage chain remains strictly valid
        verify_resp = self.client.get("/api/lens/lineage/verify")
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.json()["is_valid"])

    def test_08_single_replay_and_robustness_atlas_workflows_intact(self):
        """8. The existing Single Replay and Robustness Atlas workflows still work."""
        # Single Replay test
        replay_resp = self.client.post("/api/replays", json={
            "pcap_path": str(self.syn_fixture),
            "loss_mode": "random",
            "drop_rate": 0.10,
            "seed": 42
        })
        self.assertEqual(replay_resp.status_code, 200)
        replay_data = replay_resp.json()
        replay_id = replay_data["run_id"]

        # Wait for replay completion
        for _ in range(50):
            poll = self.client.get(f"/api/replays/{replay_id}")
            if poll.json()["status"] == "completed":
                break
            time.sleep(0.1)

        poll = self.client.get(f"/api/replays/{replay_id}")
        self.assertEqual(poll.json()["status"], "completed")

        # Robustness sweep report endpoint test
        run_id = getattr(self, "completed_sweep_id", None)
        report_resp = self.client.get(f"/api/lens/robustness-runs/{run_id}/report")
        self.assertEqual(report_resp.status_code, 200)
        report = report_resp.json()
        self.assertEqual(report["report_version"], "netguard-robustness-v1")
        self.assertIn("stability_verdict", report)
        self.assertIn("robustness_envelope", report)
        self.assertIn("atlas_matrix", report)


if __name__ == "__main__":
    unittest.main()
