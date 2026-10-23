"""Observation Robustness Atlas & Multi-Scenario Perturbation Engine.

Systematically measures how threat detection decisions change under a reproducible matrix
of controlled observation failures, rather than testing just a single loss percentage and seed.

Core Guarantees:
1. Deterministic inputs, explicit seeds, and reproducible scenario matrix.
2. Canonical time-window alignment by (source, timestamp) key across runs.
3. Fresh isolated detector state per run (no anomaly baseline leakage across scenarios).
4. Accurate packet accounting: source, eligible, dropped, retained, and realized omission rates.
5. Non-mutation: Source PCAP integrity is verified with SHA-256 before and after the sweep.
6. The non-mutation guarantee: original incident decisions in SQLite are never modified.
7. Explicit, honest stability verdicts bounded strictly to tested scenarios.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.ml.anomaly import AnomalyDetector
from backend.ml.detector import Detector
from backend.ml.replay import replay_stream, ReplayTelemetry, get_window_key
from backend.services.pcap_resolver import (
    resolve_safe_pcap_path,
    compute_pcap_fingerprint,
    verify_pcap_unmodified,
    PcapSecurityError,
)
from backend.services.replay_lab import clone_isolated_detector


@dataclass
class ScenarioConfig:
    scenario_id: str
    loss_mode: str  # random, burst, directional
    nominal_drop_rate: float
    seed: int
    burst_size: int = 4
    burst_interval: int = 20
    drop_ip: Optional[str] = None


@dataclass
class ScenarioResult:
    scenario_id: str
    loss_mode: str
    nominal_drop_rate: float
    seed: int
    burst_size: int
    burst_interval: int
    drop_ip: Optional[str]
    source_packets: int
    eligible_packets: int
    omitted_packets: int
    retained_packets: int
    realized_omission_rate: float
    eligible_omission_rate: float
    total_windows: int
    matched_windows: int
    baseline_only_windows: int
    perturbed_only_windows: int
    window_alignment_coverage: float
    baseline_suspicious_count: int
    perturbed_suspicious_count: int
    decision_shifts: int
    alert_retention_rate: float
    class_retention_rate: float
    mean_feature_shifts: Dict[str, Dict[str, Any]]
    duration_seconds: float
    status: str  # completed, cancelled, failed
    error: Optional[str] = None


@dataclass
class RobustnessRun:
    run_id: str
    pcap_path: str
    pcap_name: str
    pcap_sha256: str
    pcap_size_bytes: int
    status: str  # queued, running, completed, cancelled, failed
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    total_scenarios: int = 0
    completed_scenarios: int = 0
    current_scenario_id: Optional[str] = None
    baseline_summary: Dict[str, Any] = field(default_factory=dict)
    scenario_results: List[Dict[str, Any]] = field(default_factory=list)
    atlas_matrix: Dict[str, Any] = field(default_factory=dict)
    envelope: Dict[str, Any] = field(default_factory=dict)
    stability_verdict: str = "PENDING"  # STABLE, SENSITIVE, INCONCLUSIVE, PENDING
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "pcap_name": self.pcap_name,
            "pcap_sha256": self.pcap_sha256,
            "pcap_size_bytes": self.pcap_size_bytes,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "total_scenarios": self.total_scenarios,
            "completed_scenarios": self.completed_scenarios,
            "current_scenario_id": self.current_scenario_id,
            "baseline_summary": self.baseline_summary,
            "scenario_results": self.scenario_results,
            "atlas_matrix": self.atlas_matrix,
            "envelope": self.envelope,
            "stability_verdict": self.stability_verdict,
            "error": self.error,
            "disclaimer": "OFFLINE SIMULATION — NO PACKETS TRANSMITTED. Observation failure scenarios evaluate decision stability under hypothetical packet omission.",
        }


class RobustnessSweepEngine:
    """Orchestrates multi-scenario robustness sweeps across reproducible loss matrices."""

    def __init__(self, detector: Optional[Detector] = None, artifacts_dir: str = "artifacts"):
        self._detector = detector or Detector()
        self._artifacts_dir = Path(artifacts_dir)
        self._lock = threading.Lock()
        self._runs: Dict[str, RobustnessRun] = {}
        self._cancel_flags: Dict[str, threading.Event] = {}

    def set_detector(self, detector: Detector) -> None:
        self._detector = detector

    def build_default_scenario_matrix(
        self,
        loss_modes: Optional[List[str]] = None,
        drop_rates: Optional[List[float]] = None,
        seeds: Optional[List[int]] = None,
        burst_configs: Optional[List[Tuple[int, int]]] = None,
        drop_ips: Optional[List[str]] = None,
        max_runs: int = 50,
    ) -> List[ScenarioConfig]:
        """Constructs a bounded, deterministic matrix of observation failure scenarios."""
        modes = loss_modes or ["random", "burst", "directional"]
        rates = drop_rates or [0.05, 0.10, 0.20, 0.30, 0.50]
        seed_list = seeds or [11, 23, 37, 51, 79]
        bursts = burst_configs or [(4, 20), (8, 20)]
        target_ips = drop_ips or []

        scenarios: List[ScenarioConfig] = []

        # 1. Random Loss Ensemble across seeds and rates
        if "random" in modes:
            for rate in rates:
                for seed in seed_list:
                    if len(scenarios) >= max_runs:
                        break
                    scenarios.append(
                        ScenarioConfig(
                            scenario_id=f"random_rate{int(rate*100):02d}_seed{seed}",
                            loss_mode="random",
                            nominal_drop_rate=rate,
                            seed=seed,
                        )
                    )

        # 2. Burst Loss Scenarios
        if "burst" in modes:
            burst_rates = [r for r in rates if r in (0.10, 0.20, 0.30)] or [0.15, 0.30]
            for size, interval in bursts:
                for rate in burst_rates:
                    for seed in (seed_list[:2] if seed_list else [42]):
                        if len(scenarios) >= max_runs:
                            break
                        scenarios.append(
                            ScenarioConfig(
                                scenario_id=f"burst_s{size}_i{interval}_rate{int(rate*100):02d}_seed{seed}",
                                loss_mode="burst",
                                nominal_drop_rate=rate,
                                seed=seed,
                                burst_size=size,
                                burst_interval=interval,
                            )
                        )

        # 3. Directional Visibility Loss Scenarios
        if "directional" in modes and target_ips:
            directional_rates = [0.10, 0.25, 0.50]
            for target_ip in target_ips[:2]:  # Limit to first 2 candidate endpoints
                for rate in directional_rates:
                    for seed in (seed_list[:2] if seed_list else [42]):
                        if len(scenarios) >= max_runs:
                            break
                        safe_ip_label = target_ip.replace(".", "_").replace(":", "_")
                        scenarios.append(
                            ScenarioConfig(
                                scenario_id=f"dir_{safe_ip_label}_rate{int(rate*100):02d}_seed{seed}",
                                loss_mode="directional",
                                nominal_drop_rate=rate,
                                seed=seed,
                                drop_ip=target_ip,
                            )
                        )

        return scenarios[:max_runs]

    def create_sweep_run(
        self,
        pcap_path: str,
        loss_modes: Optional[List[str]] = None,
        drop_rates: Optional[List[float]] = None,
        seeds: Optional[List[int]] = None,
        burst_configs: Optional[List[Tuple[int, int]]] = None,
        drop_ips: Optional[List[str]] = None,
        max_runs: int = 50,
    ) -> RobustnessRun:
        resolved = resolve_safe_pcap_path(pcap_path)
        pcap_sha256, pcap_size = compute_pcap_fingerprint(resolved)

        scenarios = self.build_default_scenario_matrix(
            loss_modes=loss_modes,
            drop_rates=drop_rates,
            seeds=seeds,
            burst_configs=burst_configs,
            drop_ips=drop_ips,
            max_runs=max_runs,
        )

        run_id = f"sweep-{uuid.uuid4().hex[:12]}"
        run = RobustnessRun(
            run_id=run_id,
            pcap_path=str(resolved),
            pcap_name=resolved.name,
            pcap_sha256=pcap_sha256,
            pcap_size_bytes=pcap_size,
            status="queued",
            total_scenarios=len(scenarios),
        )

        with self._lock:
            self._runs[run_id] = run
            self._cancel_flags[run_id] = threading.Event()

        worker = threading.Thread(
            target=self._execute_sweep,
            args=(run_id, scenarios),
            daemon=True,
        )
        worker.start()
        return run

    def cancel_sweep_run(self, run_id: str) -> bool:
        with self._lock:
            if run_id in self._cancel_flags:
                self._cancel_flags[run_id].set()
            if run_id in self._runs:
                if self._runs[run_id].status in ("queued", "running"):
                    self._runs[run_id].status = "cancelled"
                    return True
        return False

    def get_sweep_run(self, run_id: str) -> Optional[dict]:
        with self._lock:
            run = self._runs.get(run_id)
            return run.to_dict() if run else None

    def list_sweep_runs(self) -> List[dict]:
        with self._lock:
            sorted_runs = sorted(self._runs.values(), key=lambda r: r.created_at, reverse=True)
            return [r.to_dict() for r in sorted_runs]

    def _execute_sweep(self, run_id: str, scenarios: List[ScenarioConfig]) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            cancel_event = self._cancel_flags.get(run_id)

        if not run or not cancel_event:
            return

        run.status = "running"
        target_path = Path(run.pcap_path)

        try:
            # 1. Source PCAP integrity check before execution
            if not verify_pcap_unmodified(target_path, run.pcap_sha256):
                raise RuntimeError("Integrity violation: Source PCAP modified before sweep.")

            # 2. Execute Baseline Run (drop_rate=0) with fresh isolated detector
            base_detector = clone_isolated_detector(self._detector)
            base_telemetry = ReplayTelemetry()
            base_windows = []

            for row in replay_stream(run.pcap_path, drop_rate=0.0, seed=0, telemetry=base_telemetry):
                if cancel_event.is_set():
                    run.status = "cancelled"
                    return
                pred = base_detector.predict(row)
                base_windows.append(pred)

            base_by_key = {get_window_key(w): w for w in base_windows}
            base_suspicious = [w for w in base_windows if w["decision"] == "SUSPECTED"]
            base_summary = self._summarize_windows(base_windows)
            run.baseline_summary = base_summary

            # 3. Iterate over the scenario matrix
            results: List[ScenarioResult] = []
            lowest_boundary: Optional[Dict[str, Any]] = None

            for sc in scenarios:
                if cancel_event.is_set():
                    run.status = "cancelled"
                    return

                run.current_scenario_id = sc.scenario_id
                t_start = time.time()

                # Clean isolated detector instance per scenario
                sc_detector = clone_isolated_detector(self._detector)
                sc_telemetry = ReplayTelemetry()
                sc_windows = []

                try:
                    for row in replay_stream(
                        run.pcap_path,
                        drop_rate=sc.nominal_drop_rate,
                        seed=sc.seed,
                        loss_mode=sc.loss_mode,
                        burst_size=sc.burst_size,
                        burst_interval=sc.burst_interval,
                        drop_ip=sc.drop_ip,
                        telemetry=sc_telemetry,
                    ):
                        if cancel_event.is_set():
                            run.status = "cancelled"
                            return
                        pred = sc_detector.predict(row)
                        sc_windows.append(pred)

                    duration = time.time() - t_start

                    # Canonical window alignment
                    pert_by_key = {get_window_key(w): w for w in sc_windows}
                    matched_keys = sorted(set(base_by_key.keys()) & set(pert_by_key.keys()))
                    base_only_keys = sorted(set(base_by_key.keys()) - set(pert_by_key.keys()))
                    pert_only_keys = sorted(set(pert_by_key.keys()) - set(base_by_key.keys()))

                    coverage = round(len(matched_keys) / max(len(base_by_key), 1), 4)

                    pert_suspicious = [w for w in sc_windows if w["decision"] == "SUSPECTED"]

                    # Decision & class retention analysis over baseline suspected windows
                    decision_shifts = 0
                    retained_alerts = 0
                    retained_classes = 0
                    first_shifted_key: Optional[str] = None

                    for b_win in base_suspicious:
                        k = get_window_key(b_win)
                        if k in pert_by_key:
                            p_win = pert_by_key[k]
                            if p_win["decision"] == "SUSPECTED":
                                retained_alerts += 1
                                if p_win["prediction"] == b_win["prediction"]:
                                    retained_classes += 1
                                else:
                                    decision_shifts += 1
                                    if not first_shifted_key:
                                        first_shifted_key = k
                            else:
                                decision_shifts += 1
                                if not first_shifted_key:
                                    first_shifted_key = k
                        else:
                            # Omitted window where threat was not detected
                            decision_shifts += 1
                            if not first_shifted_key:
                                first_shifted_key = k

                    num_sus = len(base_suspicious)
                    alert_retention = round(retained_alerts / num_sus, 4) if num_sus > 0 else 1.0
                    class_retention = round(retained_classes / num_sus, 4) if num_sus > 0 else 1.0

                    # Check lowest tested instability boundary
                    if decision_shifts > 0 and num_sus > 0:
                        if lowest_boundary is None or sc.nominal_drop_rate < lowest_boundary["nominal_drop_rate"]:
                            lowest_boundary = {
                                "scenario_id": sc.scenario_id,
                                "loss_mode": sc.loss_mode,
                                "nominal_drop_rate": sc.nominal_drop_rate,
                                "realized_omission_rate": sc_telemetry.realized_omission_rate,
                                "seed": sc.seed,
                                "first_affected_window": first_shifted_key,
                                "decision_shifts": decision_shifts,
                            }

                    # Feature drift
                    sc_summary = self._summarize_windows(sc_windows)
                    feature_shifts = self._compare_features(
                        base_summary["mean_features"],
                        sc_summary["mean_features"]
                    )

                    result = ScenarioResult(
                        scenario_id=sc.scenario_id,
                        loss_mode=sc.loss_mode,
                        nominal_drop_rate=sc.nominal_drop_rate,
                        seed=sc.seed,
                        burst_size=sc.burst_size,
                        burst_interval=sc.burst_interval,
                        drop_ip=sc.drop_ip,
                        source_packets=sc_telemetry.source_packets,
                        eligible_packets=sc_telemetry.eligible_packets,
                        omitted_packets=sc_telemetry.omitted_packets,
                        retained_packets=sc_telemetry.retained_packets,
                        realized_omission_rate=sc_telemetry.realized_omission_rate,
                        eligible_omission_rate=sc_telemetry.eligible_omission_rate,
                        total_windows=len(sc_windows),
                        matched_windows=len(matched_keys),
                        baseline_only_windows=len(base_only_keys),
                        perturbed_only_windows=len(pert_only_keys),
                        window_alignment_coverage=coverage,
                        baseline_suspicious_count=len(base_suspicious),
                        perturbed_suspicious_count=len(pert_suspicious),
                        decision_shifts=decision_shifts,
                        alert_retention_rate=alert_retention,
                        class_retention_rate=class_retention,
                        mean_feature_shifts=feature_shifts,
                        duration_seconds=round(duration, 3),
                        status="completed",
                    )
                    results.append(result)

                except Exception as ex:
                    results.append(
                        ScenarioResult(
                            scenario_id=sc.scenario_id,
                            loss_mode=sc.loss_mode,
                            nominal_drop_rate=sc.nominal_drop_rate,
                            seed=sc.seed,
                            burst_size=sc.burst_size,
                            burst_interval=sc.burst_interval,
                            drop_ip=sc.drop_ip,
                            source_packets=0,
                            eligible_packets=0,
                            omitted_packets=0,
                            retained_packets=0,
                            realized_omission_rate=0.0,
                            eligible_omission_rate=0.0,
                            total_windows=0,
                            matched_windows=0,
                            baseline_only_windows=0,
                            perturbed_only_windows=0,
                            window_alignment_coverage=0.0,
                            baseline_suspicious_count=len(base_suspicious),
                            perturbed_suspicious_count=0,
                            decision_shifts=0,
                            alert_retention_rate=0.0,
                            class_retention_rate=0.0,
                            mean_feature_shifts={},
                            duration_seconds=0.0,
                            status="failed",
                            error=str(ex),
                        )
                    )

                run.completed_scenarios += 1

            # 4. Verify PCAP non-mutation after complete sweep
            if not verify_pcap_unmodified(target_path, run.pcap_sha256):
                raise RuntimeError("Integrity violation: Source PCAP modified during sweep execution.")

            # 5. Build Atlas matrix (loss_mode x nominal_rate)
            matrix = self._build_atlas_matrix(results)

            # 6. Compute aggregate stability verdict
            verdict = self._compute_overall_verdict(base_suspicious, results)

            # 7. Construct robustness envelope
            envelope = self._build_robustness_envelope(base_suspicious, results, lowest_boundary)

            run.scenario_results = [r.__dict__ for r in results]
            run.atlas_matrix = matrix
            run.envelope = envelope
            run.stability_verdict = verdict
            run.status = "completed"
            run.completed_at = time.time()
            run.current_scenario_id = None

        except Exception as error:
            run.status = "failed"
            run.error = str(error)
            run.completed_at = time.time()
            run.current_scenario_id = None

    def _build_atlas_matrix(self, results: List[ScenarioResult]) -> Dict[str, Any]:
        """Organizes results into a structured matrix of loss_mode x nominal_rate."""
        matrix: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for r in results:
            if r.status != "completed":
                continue
            mode = r.loss_mode
            rate_key = f"{int(r.nominal_drop_rate * 100)}%"
            if mode not in matrix:
                matrix[mode] = {}
            if rate_key not in matrix[mode]:
                matrix[mode][rate_key] = []

            matrix[mode][rate_key].append({
                "scenario_id": r.scenario_id,
                "seed": r.seed,
                "realized_omission_rate": r.realized_omission_rate,
                "alert_retention_rate": r.alert_retention_rate,
                "class_retention_rate": r.class_retention_rate,
                "decision_shifts": r.decision_shifts,
                "coverage": r.window_alignment_coverage,
            })

        # Calculate cell averages
        matrix_cells: List[Dict[str, Any]] = []
        for mode, rates in matrix.items():
            for rate_key, runs in rates.items():
                n = len(runs)
                avg_retention = round(sum(run["alert_retention_rate"] for run in runs) / n, 4) if n > 0 else 0.0
                avg_realized = round(sum(run["realized_omission_rate"] for run in runs) / n, 4) if n > 0 else 0.0
                total_shifts = sum(run["decision_shifts"] for run in runs)
                matrix_cells.append({
                    "loss_mode": mode,
                    "nominal_rate": rate_key,
                    "runs_count": n,
                    "avg_alert_retention": avg_retention,
                    "avg_realized_omission": avg_realized,
                    "total_decision_shifts": total_shifts,
                    "is_stable": total_shifts == 0 and avg_retention == 1.0,
                })

        return {
            "modes": list(matrix.keys()),
            "cells": matrix_cells,
        }

    def _compute_overall_verdict(
        self,
        base_suspicious: List[dict],
        results: List[ScenarioResult]
    ) -> str:
        """Determines honest aggregate verdict: INCONCLUSIVE, SENSITIVE, or STABLE."""
        valid_results = [r for r in results if r.status == "completed"]
        if not valid_results:
            return "INCONCLUSIVE"

        if len(base_suspicious) == 0:
            return "INCONCLUSIVE"  # Baseline had zero threats to test

        # If any tested scenario experienced decision shifts or dropped alert retention below 1.0
        has_shifts = any(r.decision_shifts > 0 or r.alert_retention_rate < 1.0 for r in valid_results)
        if has_shifts:
            return "SENSITIVE"

        return "STABLE"

    def _build_robustness_envelope(
        self,
        base_suspicious: List[dict],
        results: List[ScenarioResult],
        lowest_boundary: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        valid = [r for r in results if r.status == "completed"]
        num_valid = len(valid)

        if num_valid == 0:
            return {"tested_scenarios": 0, "status": "NO_VALID_RUNS"}

        mean_alert_ret = round(sum(r.alert_retention_rate for r in valid) / num_valid, 4)
        mean_class_ret = round(sum(r.class_retention_rate for r in valid) / num_valid, 4)
        total_shifts = sum(r.decision_shifts for r in valid)
        mean_realized_drop = round(sum(r.realized_omission_rate for r in valid) / num_valid, 4)

        return {
            "tested_scenarios_count": num_valid,
            "baseline_threat_windows": len(base_suspicious),
            "mean_alert_retention_rate": mean_alert_ret,
            "mean_class_retention_rate": mean_class_ret,
            "total_decision_shifts_across_all_runs": total_shifts,
            "mean_realized_omission_rate": mean_realized_drop,
            "lowest_tested_boundary": lowest_boundary,
            "tested_loss_modes": sorted(list(set(r.loss_mode for r in valid))),
            "tested_drop_rates": sorted(list(set(r.nominal_drop_rate for r in valid))),
            "tested_seeds": sorted(list(set(r.seed for r in valid))),
            "verdict_scope": "Tested scenario space only; does not imply universal robustness to unobserved impairments.",
        }

    def _summarize_windows(self, windows: List[dict]) -> dict:
        if not windows:
            return {"total_windows": 0, "predictions": {}, "mean_features": {}}

        predictions: Dict[str, int] = {}
        feature_accum: Dict[str, float] = {}

        for w in windows:
            pred = w["prediction"]
            predictions[pred] = predictions.get(pred, 0) + 1
            for k, val in w["features"].items():
                feature_accum[k] = feature_accum.get(k, 0.0) + float(val)

        n = len(windows)
        mean_features = {k: round(v / n, 4) for k, v in feature_accum.items()}

        return {
            "total_windows": n,
            "predictions": predictions,
            "mean_features": mean_features,
        }

    def _compare_features(self, base: Dict[str, float], pert: Dict[str, float]) -> Dict[str, dict]:
        shifts = {}
        for k in ('syn_rate', 'completed_fraction', 'bytes_per_second', 'unique_ports', 'packets'):
            b_val = base.get(k, 0.0)
            p_val = pert.get(k, 0.0)
            diff = round(p_val - b_val, 4)
            pct = round((diff / b_val) * 100, 2) if b_val != 0 else None
            shifts[k] = {
                "baseline": b_val,
                "perturbed": p_val,
                "difference": diff,
                "percentage_change": pct,
            }
        return shifts
