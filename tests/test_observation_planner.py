import unittest
from backend.services.observation_planner import PassiveNextObservationPlanner


class TestObservationPlanner(unittest.TestCase):
    def setUp(self):
        self.planner = PassiveNextObservationPlanner()

    def test_empty_input_returns_insufficient_evidence(self):
        plan = self.planner.generate_plan()
        self.assertEqual(plan.status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(plan.total_recommendations, 0)
        self.assertFalse(plan.active_network_action)

    def test_zero_active_network_actions_invariant(self):
        # Even with various gaps, active_network_action must ALWAYS be False
        mock_passport = {
            "alert_id": "alt-test-01",
            "capture_quality": {
                "overall_status": "DEGRADED",
                "indicators": [
                    {"name": "kernel_drops", "status": "UNAVAILABLE", "value": None},
                    {"name": "queue_drops", "status": "DEGRADED", "value": 50},
                ]
            },
            "fragility": {"status": "SENSITIVE", "handshake_ambiguity": True},
        }
        mock_sweep = {
            "run_id": "sweep-test-01",
            "stability_verdict": "SENSITIVE",
            "envelope": {
                "total_decision_shifts_across_all_runs": 3,
                "lowest_tested_boundary": {
                    "scenario_id": "random_rate10_seed11",
                    "nominal_drop_rate": 0.10,
                }
            }
        }
        plan = self.planner.generate_plan(passport=mock_passport, sweep_run=mock_sweep)
        self.assertFalse(plan.active_network_action)
        for rec in plan.recommendations:
            self.assertFalse(rec["active_network_action"])
            self.assertIn("rule_id", rec)
            self.assertIn("trigger_evidence", rec)

    def test_kernel_drops_unavailable_triggers_capture_health_rule(self):
        mock_passport = {
            "alert_id": "alt-01",
            "capture_quality": {
                "indicators": [
                    {"name": "kernel_drops", "status": "UNAVAILABLE", "value": None}
                ]
            }
        }
        plan = self.planner.generate_plan(passport=mock_passport)
        rule_ids = [r["rule_id"] for r in plan.recommendations]
        self.assertIn("OBS-CAP-01", rule_ids)
        cap_rec = next(r for r in plan.recommendations if r["rule_id"] == "OBS-CAP-01")
        self.assertEqual(cap_rec["priority"], "HIGH")
        self.assertIn("unavailable", cap_rec["trigger_evidence"].lower())

    def test_sweep_instability_triggers_controlled_replay_rule(self):
        mock_sweep = {
            "run_id": "sweep-02",
            "stability_verdict": "SENSITIVE",
            "envelope": {
                "total_decision_shifts_across_all_runs": 5,
                "lowest_tested_boundary": {
                    "scenario_id": "burst_s4_i20_rate20_seed11",
                    "nominal_drop_rate": 0.20,
                }
            }
        }
        plan = self.planner.generate_plan(sweep_run=mock_sweep)
        rule_ids = [r["rule_id"] for r in plan.recommendations]
        self.assertIn("OBS-SWEEP-01", rule_ids)
        sweep_rec = next(r for r in plan.recommendations if r["rule_id"] == "OBS-SWEEP-01")
        self.assertEqual(sweep_rec["priority"], "HIGH")
        self.assertIn("burst_s4_i20_rate20_seed11", sweep_rec["justifying_scenario"])

    def test_deterministic_scoring_order(self):
        passport = {
            "alert_id": "alt-det",
            "capture_quality": {
                "indicators": [
                    {"name": "queue_drops", "status": "DEGRADED", "value": 20},
                    {"name": "kernel_drops", "status": "UNAVAILABLE", "value": None},
                ]
            },
            "fragility": {"status": "SENSITIVE", "handshake_ambiguity": True},
        }
        plan1 = self.planner.generate_plan(passport=passport)
        plan2 = self.planner.generate_plan(passport=passport)
        # Deterministic recommendations list and scores
        self.assertEqual([r["rule_id"] for r in plan1.recommendations], [r["rule_id"] for r in plan2.recommendations])
        self.assertEqual([r["score"] for r in plan1.recommendations], [r["score"] for r in plan2.recommendations])


if __name__ == "__main__":
    unittest.main()
