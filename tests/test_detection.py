import unittest
from backend.ml.detector import Detector, evaluate_rules, baseline
from backend.ml.anomaly import AnomalyDetector


class DetectionTests(unittest.TestCase):
    def test_explainable_rules(self):
        # Scan features
        scan_features = {"unique_ports": 25, "syn_rate": 5.0, "bytes_per_second": 2000, "completed_fraction": 0.0}
        self.assertEqual(baseline(scan_features), "PORT_SCAN")
        evals = evaluate_rules(scan_features)
        scan_rule = next(r for r in evals if r["rule_id"] == "RULE-SCAN-01")
        self.assertTrue(scan_rule["triggered"])
        self.assertEqual(scan_rule["measured_values"]["unique_ports"], 25.0)
        self.assertEqual(scan_rule["units"]["syn_rate"], "packets/sec")

        # SYN Flood features
        syn_features = {"syn_rate": 45.0, "completed_fraction": 0.02, "unique_ports": 1, "bytes_per_second": 3000}
        self.assertEqual(baseline(syn_features), "SYN_FLOOD")
        evals_syn = evaluate_rules(syn_features)
        syn_rule = next(r for r in evals_syn if r["rule_id"] == "RULE-SYN-01")
        self.assertTrue(syn_rule["triggered"])

    def test_anomaly_detector_warmup_and_detection(self):
        ad = AnomalyDetector(min_warmup_windows=5)
        benign_sample = {
            "packets": 10, "bytes_per_second": 1000, "unique_ports": 2, "unique_hosts": 1,
            "syn_rate": 0.5, "rst_fraction": 0.0, "response_fraction": 0.5, "mean_size": 100,
            "udp_fraction": 0.1, "icmp_fraction": 0.0, "mean_gap": 0.1, "completed_fraction": 0.9
        }

        # 1. Warm-up state
        score1 = ad.score(benign_sample)
        self.assertEqual(score1["status"], "WARM_UP")
        self.assertFalse(score1["is_anomalous"])

        # 2. Feed 5 samples to complete warm-up
        for _ in range(5):
            ad.feed_baseline_sample(benign_sample)
        self.assertTrue(ad.is_ready)

        # 3. Score benign sample after warmup
        score_normal = ad.score(benign_sample)
        self.assertEqual(score_normal["status"], "READY")
        self.assertFalse(score_normal["is_anomalous"])

        # 4. Score extreme outlier
        outlier = {
            "packets": 5000, "bytes_per_second": 900000, "unique_ports": 800, "unique_hosts": 400,
            "syn_rate": 800.0, "rst_fraction": 0.9, "response_fraction": 0.0, "mean_size": 1400,
            "udp_fraction": 0.8, "icmp_fraction": 0.8, "mean_gap": 0.0001, "completed_fraction": 0.0
        }
        score_outlier = ad.score(outlier)
        self.assertEqual(score_outlier["status"], "READY")
        self.assertTrue(score_outlier["is_anomalous"])
        self.assertEqual(score_outlier["label"], "ANOMALOUS_UNKNOWN_PATTERN")

    def test_detector_fallback_when_model_absent(self):
        detector = Detector(model_path="non_existent_model.joblib")
        self.assertFalse(detector.model_available)

        row = {
            "features": {"unique_ports": 20, "syn_rate": 5.0, "bytes_per_second": 1000, "completed_fraction": 0.0},
            "quality": {"state_evictions": 0, "late_packets": 0, "queue_drops": 0}
        }
        res = detector.predict(row)
        self.assertEqual(res["decision"], "SUSPECTED")
        self.assertEqual(res["prediction"], "PORT_SCAN")
        self.assertEqual(res["fusion"]["agreement_status"], "RULE_ONLY")
        self.assertFalse(res["model_available"])

    def test_degraded_quality_marks_finding_uncertain(self):
        detector = Detector(model_path="non_existent_model.joblib")
        row = {
            "features": {"unique_ports": 20, "syn_rate": 5.0, "bytes_per_second": 1000, "completed_fraction": 0.0},
            "quality": {"state_evictions": 2, "late_packets": 0, "queue_drops": 0}
        }
        res = detector.predict(row)
        self.assertEqual(res["prediction"], "PORT_SCAN")
        self.assertEqual(res["decision"], "UNCERTAIN")
        self.assertEqual(res["fusion"]["evidence_quality"], "DEGRADED")
