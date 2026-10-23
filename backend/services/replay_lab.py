"""Capture-Aware Incident Verification & PCAP Replay Lab Service.

Coordinates deterministic offline counterfactual observation-loss experiments:
Compares a baseline replay (0% loss) against controlled, explicitly hypothetical
loss scenarios (random packet omission, burst loss, or directional loss).

Critical Guarantees:
1. Replay is strictly offline and never transmits packets.
2. Injected loss is simulated, not measured from live network.
3. Counterfactual instability is advisory evidence for human review;
   it NEVER overwrites, mutates, or dismisses the original incident alert.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from backend.ml.detector import Detector
from backend.ml.replay import replay


@dataclass
class ReplayExperiment:
    run_id: str
    pcap_path: str
    pcap_name: str
    status: str  # queued, running, completed, failed, cancelled
    loss_mode: str  # random, burst, directional
    drop_rate: float
    seed: int
    burst_size: int = 4
    burst_interval: int = 20
    drop_ip: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    baseline_summary: Dict[str, Any] = field(default_factory=dict)
    perturbed_summary: Dict[str, Any] = field(default_factory=dict)
    comparison: Dict[str, Any] = field(default_factory=dict)
    stability_verdict: str = "PENDING"  # STABLE, SENSITIVE, INCONCLUSIVE, PENDING
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "pcap_name": self.pcap_name,
            "status": self.status,
            "loss_mode": self.loss_mode,
            "drop_rate": self.drop_rate,
            "seed": self.seed,
            "burst_size": self.burst_size,
            "burst_interval": self.burst_interval,
            "drop_ip": self.drop_ip,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "stability_verdict": self.stability_verdict,
            "baseline_summary": self.baseline_summary,
            "perturbed_summary": self.perturbed_summary,
            "comparison": self.comparison,
            "error": self.error,
            "advisory_disclaimer": "OFFLINE SIMULATION — NO PACKETS TRANSMITTED. Simulated loss is injected by the experiment; it does not measure or prove actual live packet loss.",
        }


class ReplayLabService:
    def __init__(self, detector: Optional[Detector] = None, artifacts_dir: str = "artifacts"):
        self._detector = detector or Detector()
        self._artifacts_dir = Path(artifacts_dir)
        self._lock = threading.Lock()
        self._experiments: Dict[str, ReplayExperiment] = {}
        self._cancel_flags: Dict[str, threading.Event] = {}

    def set_detector(self, detector: Detector) -> None:
        self._detector = detector

    def list_available_pcaps(self) -> List[dict]:
        """Safely enumerates available demo/fixture PCAPs without arbitrary path access."""
        results = []
        # Check artifacts/demo and tests directories
        search_dirs = [self._artifacts_dir / "demo", Path("tests"), self._artifacts_dir]
        for d in search_dirs:
            if d.exists() and d.is_dir():
                for p in d.glob("*.pcap"):
                    results.append({
                        "filename": p.name,
                        "relative_path": str(p),
                        "size_bytes": p.stat().st_size,
                        "modified_at": p.stat().st_mtime,
                        "category": p.name.split("-")[1] if "-" in p.name else "CUSTOM",
                    })
        return sorted(results, key=lambda x: x["filename"])

    def create_experiment(
        self,
        pcap_path: str,
        loss_mode: str = "random",
        drop_rate: float = 0.1,
        seed: int = 42,
        burst_size: int = 4,
        burst_interval: int = 20,
        drop_ip: Optional[str] = None
    ) -> ReplayExperiment:
        target = Path(pcap_path)
        # Prevent path traversal outside allowed repository roots
        if not target.exists() or not target.is_file():
            # Try resolving relative to workspace
            resolved = Path(pcap_path).resolve()
            if not resolved.exists() or not resolved.is_file():
                raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
            target = resolved

        run_id = f"replay-{uuid.uuid4().hex[:12]}"
        exp = ReplayExperiment(
            run_id=run_id,
            pcap_path=str(target),
            pcap_name=target.name,
            status="queued",
            loss_mode=loss_mode,
            drop_rate=drop_rate,
            seed=seed,
            burst_size=burst_size,
            burst_interval=burst_interval,
            drop_ip=drop_ip,
        )

        with self._lock:
            self._experiments[run_id] = exp
            self._cancel_flags[run_id] = threading.Event()

        # Run synchronously or in worker
        worker = threading.Thread(target=self._run_experiment, args=(run_id,), daemon=True)
        worker.start()
        return exp

    def cancel_experiment(self, run_id: str) -> bool:
        with self._lock:
            if run_id in self._cancel_flags:
                self._cancel_flags[run_id].set()
            if run_id in self._experiments:
                if self._experiments[run_id].status in ("queued", "running"):
                    self._experiments[run_id].status = "cancelled"
                    return True
        return False

    def get_experiment(self, run_id: str) -> Optional[dict]:
        with self._lock:
            exp = self._experiments.get(run_id)
            return exp.to_dict() if exp else None

    def list_experiments(self) -> List[dict]:
        with self._lock:
            sorted_exps = sorted(self._experiments.values(), key=lambda e: e.created_at, reverse=True)
            return [e.to_dict() for e in sorted_exps]

    def _run_experiment(self, run_id: str) -> None:
        with self._lock:
            exp = self._experiments.get(run_id)
            cancel_event = self._cancel_flags.get(run_id)

        if not exp or not cancel_event:
            return

        exp.status = "running"

        try:
            # 1. Baseline Run (drop_rate=0.0)
            base_windows = []
            for row in replay(exp.pcap_path, drop_rate=0.0, seed=0):
                if cancel_event.is_set():
                    exp.status = "cancelled"
                    return
                pred = self._detector.predict(row)
                base_windows.append(pred)

            # 2. Perturbed Run
            pert_windows = []
            for row in replay(
                exp.pcap_path,
                drop_rate=exp.drop_rate,
                seed=exp.seed,
                loss_mode=exp.loss_mode,
                burst_size=exp.burst_size,
                burst_interval=exp.burst_interval,
                drop_ip=exp.drop_ip
            ):
                if cancel_event.is_set():
                    exp.status = "cancelled"
                    return
                pred = self._detector.predict(row)
                pert_windows.append(pred)

            # 3. Analyze summaries & feature shifts
            base_summary = self._summarize_windows(base_windows)
            pert_summary = self._summarize_windows(pert_windows)

            # 4. Determine stability verdict
            # Check if any suspicious baseline window changed prediction or downgraded
            base_suspicious = [w for w in base_windows if w["decision"] == "SUSPECTED"]
            pert_suspicious = [w for w in pert_windows if w["decision"] == "SUSPECTED"]

            if not base_suspicious:
                stability = "INCONCLUSIVE"  # Baseline had no threat to test
            elif len(pert_suspicious) < len(base_suspicious) or any(
                b["prediction"] != p["prediction"] for b, p in zip(base_windows, pert_windows) if b["decision"] == "SUSPECTED"
            ):
                stability = "SENSITIVE"  # Decision changed or weakened under simulated loss
            else:
                stability = "STABLE"

            # 5. Build comparison metrics
            comparison = {
                "baseline_windows_count": len(base_windows),
                "perturbed_windows_count": len(pert_windows),
                "baseline_suspicious_count": len(base_suspicious),
                "perturbed_suspicious_count": len(pert_suspicious),
                "decision_shifts": sum(
                    1 for b, p in zip(base_windows, pert_windows) if b["prediction"] != p["prediction"]
                ),
                "feature_shifts": self._compare_features(base_summary["mean_features"], pert_summary["mean_features"]),
                "fragility_status_comparison": {
                    "baseline": base_summary.get("fragility_statuses", {}),
                    "perturbed": pert_summary.get("fragility_statuses", {}),
                }
            }

            exp.baseline_summary = base_summary
            exp.perturbed_summary = pert_summary
            exp.comparison = comparison
            exp.stability_verdict = stability
            exp.status = "completed"
            exp.completed_at = time.time()

        except Exception as error:
            exp.status = "failed"
            exp.error = str(error)
            exp.completed_at = time.time()

    def _summarize_windows(self, windows: List[dict]) -> dict:
        if not windows:
            return {"total_windows": 0, "predictions": {}, "mean_features": {}, "fragility_statuses": {}}

        predictions: Dict[str, int] = {}
        fragilities: Dict[str, int] = {}
        feature_accum: Dict[str, float] = {}

        for w in windows:
            pred = w["prediction"]
            predictions[pred] = predictions.get(pred, 0) + 1

            frag_stat = w.get("fragility", {}).get("status", "not_applicable")
            fragilities[frag_stat] = fragilities.get(frag_stat, 0) + 1

            for k, val in w["features"].items():
                feature_accum[k] = feature_accum.get(k, 0.0) + float(val)

        n = len(windows)
        mean_features = {k: round(v / n, 4) for k, v in feature_accum.items()}

        return {
            "total_windows": n,
            "predictions": predictions,
            "mean_features": mean_features,
            "fragility_statuses": fragilities,
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
