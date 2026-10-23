import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.storage.evidence_lineage import (
    EvidenceLineageService,
    canonical_json_dumps,
    compute_manifest_digest,
    calculate_event_hash,
    GENESIS_PREVIOUS_HASH,
)


class TestEvidenceLineage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_lineage.db"
        self.service = EvidenceLineageService(db_path=str(self.db_path))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_canonical_json_dumps_determinism(self):
        obj1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        obj2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
        # Keys must be sorted, compact separators (no whitespace after ':' or ',')
        self.assertEqual(canonical_json_dumps(obj1), canonical_json_dumps(obj2))
        self.assertEqual(canonical_json_dumps(obj1), '{"a":2,"m":{"a":4,"b":3},"z":1}')

    def test_empty_lineage_verification(self):
        res = self.service.verify_chain()
        self.assertEqual(res["status"], "EMPTY")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["events_count"], 0)

    def test_genesis_event_and_chain_continuity(self):
        evt1 = self.service.record_event(
            event_type="INCIDENT_RECORDED",
            manifest_data={"alert_id": "alt-001", "class": "SYN_FLOOD"}
        )
        self.assertEqual(evt1["sequence_id"], 1)
        self.assertEqual(evt1["previous_hash"], GENESIS_PREVIOUS_HASH)

        evt2 = self.service.record_event(
            event_type="ROBUSTNESS_SWEEP_QUEUED",
            manifest_data={"run_id": "swp-001", "scenarios": 10},
            parent_id="alt-001"
        )
        self.assertEqual(evt2["sequence_id"], 2)
        self.assertEqual(evt2["previous_hash"], evt1["event_hash"])

        evt3 = self.service.record_event(
            event_type="OBSERVATION_PLAN_GENERATED",
            manifest_data={"plan_id": "pln-001", "recommendations": ["OBS-CAP-01"]},
            parent_id="swp-001"
        )
        self.assertEqual(evt3["sequence_id"], 3)
        self.assertEqual(evt3["previous_hash"], evt2["event_hash"])

        # Verification must pass
        verify_res = self.service.verify_chain()
        self.assertEqual(verify_res["status"], "VALID")
        self.assertTrue(verify_res["is_valid"])
        self.assertEqual(verify_res["events_count"], 3)
        self.assertEqual(verify_res["head_hash"], evt3["event_hash"])

    def test_tamper_detection_manifest_modification(self):
        self.service.record_event("EVENT_A", {"value": 100})
        self.service.record_event("EVENT_B", {"value": 200})

        # Deliberately modify SQLite record without updating manifest_digest
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("UPDATE lineage_events SET manifest_json = '{\"tampered\":true}' WHERE sequence_id = 1")
        conn.commit()
        conn.close()

        verify_res = self.service.verify_chain()
        self.assertEqual(verify_res["status"], "INVALID")
        self.assertFalse(verify_res["is_valid"])
        self.assertEqual(verify_res["failing_sequence_id"], 1)
        self.assertIn("tampered", verify_res["error_reason"].lower())

    def test_tamper_detection_hash_chain_break(self):
        self.service.record_event("EVENT_A", {"value": 100})
        self.service.record_event("EVENT_B", {"value": 200})

        # Break previous_hash linkage
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("UPDATE lineage_events SET previous_hash = '1' || SUBSTR(previous_hash, 2) WHERE sequence_id = 2")
        conn.commit()
        conn.close()

        verify_res = self.service.verify_chain()
        self.assertEqual(verify_res["status"], "INVALID")
        self.assertFalse(verify_res["is_valid"])
        self.assertEqual(verify_res["failing_sequence_id"], 2)
        self.assertIn("break", verify_res["error_reason"].lower())

    def test_evidence_bundle_generation(self):
        evt = self.service.record_event("EXPERIMENT_COMPLETED", {"status": "SUCCESS", "shifts": 0})
        bundle = self.service.build_evidence_bundle(evt["event_id"])
        self.assertEqual(bundle["bundle_version"], "netguard-bundle-v1")
        self.assertIn("target_event", bundle)
        self.assertEqual(bundle["target_event"]["event_id"], evt["event_id"])
        self.assertEqual(bundle["lineage_verification"]["status"], "VALID")
        self.assertIn("security_disclaimer", bundle)


if __name__ == "__main__":
    unittest.main()
