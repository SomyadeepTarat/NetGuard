"""Generates reproducible research artifacts for the Evidence Resilience Engine (ERE).

Executes an Observation Robustness Atlas sweep, Passive Next-Observation Planner,
and Tamper-Evident Evidence Lineage verification over authorized demo PCAP fixtures.
Saves reproducible JSON reports and bundles into artifacts/research/.
"""
import json
from pathlib import Path
import time

from backend.ml.detector import Detector
from backend.ml.robustness_sweep import RobustnessSweepEngine
from backend.services.observation_planner import PassiveNextObservationPlanner
from backend.storage.evidence_lineage import EvidenceLineageService
from backend.services.pcap_resolver import resolve_safe_pcap_path, compute_pcap_fingerprint


def main():
    research_dir = Path("artifacts/research")
    research_dir.mkdir(parents=True, exist_ok=True)

    demo_pcap = "artifacts/demo/test-SYN_FLOOD-0.pcap"
    resolved_pcap = resolve_safe_pcap_path(demo_pcap)
    pcap_sha256, pcap_size = compute_pcap_fingerprint(resolved_pcap)

    print(f"[*] Target source capture: {resolved_pcap.name} (SHA-256: {pcap_sha256[:16]}...)")

    detector = Detector()
    sweep_engine = RobustnessSweepEngine(detector=detector)
    lineage_service = EvidenceLineageService(db_path="artifacts/netguard_incidents.db")
    planner = PassiveNextObservationPlanner()

    # 1. Execute Bounded Robustness Sweep Matrix
    print("[*] Executing Observation Robustness Sweep across loss modes & seed ensemble...")
    run = sweep_engine.create_sweep_run(
        pcap_path=str(resolved_pcap),
        loss_modes=["random", "burst", "directional"],
        drop_rates=[0.05, 0.10, 0.20, 0.30],
        seeds=[11, 23, 37, 51, 79],
        max_runs=25
    )

    while run.status in ("queued", "running"):
        time.sleep(0.5)

    print(f"[+] Sweep completed with status: {run.status} | Verdict: {run.stability_verdict}")
    print(f"[+] Total scenarios evaluated: {run.completed_scenarios}/{run.total_scenarios}")

    sweep_report = {
        "report_version": "netguard-robustness-v1",
        "generated_at": time.time(),
        "run_id": run.run_id,
        "source_capture": {
            "pcap_name": run.pcap_name,
            "pcap_sha256": run.pcap_sha256,
            "pcap_size_bytes": run.pcap_size_bytes,
        },
        "stability_verdict": run.stability_verdict,
        "robustness_envelope": run.envelope,
        "atlas_matrix": run.atlas_matrix,
        "baseline_summary": run.baseline_summary,
        "scenarios_evaluated": run.completed_scenarios,
        "scenarios": run.scenario_results,
        "reproducibility_contract": {
            "modes_tested": ["random", "burst", "directional"],
            "rates_tested": [0.05, 0.10, 0.20, 0.30],
            "seeds_tested": [11, 23, 37, 51, 79],
        }
    }

    sweep_path = research_dir / f"robustness_sweep_{run.run_id}.json"
    sweep_path.write_text(json.dumps(sweep_report, indent=2))
    print(f"[+] Saved robustness report: {sweep_path}")

    # 2. Record Sweep in Evidence Lineage
    lineage_evt = lineage_service.record_event(
        event_type="ROBUSTNESS_SWEEP_COMPLETED",
        manifest_data={
            "run_id": run.run_id,
            "source_pcap": run.pcap_name,
            "source_sha256": run.pcap_sha256,
            "stability_verdict": run.stability_verdict,
            "mean_retention": run.envelope.get("mean_alert_retention_rate"),
            "evaluated_runs": run.completed_scenarios,
        },
        parent_id=None,
    )
    print(f"[+] Lineage event recorded: #{lineage_evt['sequence_id']} (Hash: {lineage_evt['event_hash'][:16]}...)")

    # 3. Generate Passive Next-Observation Plan
    print("[*] Generating Passive Next-Observation Plan...")
    mock_passport = {
        "alert_id": f"alt-{run.run_id[:8]}",
        "detector_class": "SYN_FLOOD",
        "decision": "SUSPECTED",
        "capture_quality": {
            "overall_status": "DEGRADED",
            "indicators": [
                {"name": "Kernel Drops", "status": "UNAVAILABLE", "value": None},
                {"name": "Queue Drops", "status": "HEALTHY", "value": 0},
            ]
        },
        "fragility": {"status": "FRAGILE", "minimum_tested_pairs_to_change": 3},
        "evidence": {"response_fraction": 0.02, "completed_fraction": 0.0},
    }
    plan = planner.generate_plan(passport=mock_passport, sweep_run=run.to_dict())
    plan_path = research_dir / f"observation_plan_{run.run_id}.json"
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2))
    print(f"[+] Saved observation plan: {plan_path} ({plan.total_recommendations} recommendations)")

    # 4. Verify Hash Chain Integrity
    verify_result = lineage_service.verify_chain()
    print(f"[+] Lineage Verification Status: {verify_result['status']} ({verify_result['events_count']} blocks checked)")

    # 5. Build Reproducible Evidence Bundle
    bundle = lineage_service.build_evidence_bundle(lineage_evt["event_id"])
    bundle_path = research_dir / f"evidence_bundle_{run.run_id}.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))
    print(f"[+] Saved reproducible evidence bundle: {bundle_path}")


if __name__ == "__main__":
    main()
