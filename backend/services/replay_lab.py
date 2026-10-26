"""Capture-Aware Incident Verification & PCAP Replay Lab Service.

Coordinates deterministic offline counterfactual observation-loss experiments:
Compares a baseline replay (0% loss) against controlled, explicitly hypothetical
loss scenarios (random packet omission, burst loss, or directional loss).

Critical Guarantees:
1. Replay is strictly offline and never transmits packets.
2. Injected loss is simulated, not measured from live network.
3. Counterfactual instability is advisory evidence for human review;
   it NEVER overwrites, mutates, or dismisses the original incident alert.
4. Input PCAPs are resolved securely against allowlisted directories and verified for non-mutation.
"""
from dataclasses import dataclass, field
from pathlib import Path
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from backend.ml.anomaly import AnomalyDetector
from backend.ml.detector import Detector
from backend.ml.replay import replay_stream, ReplayTelemetry
from backend.services.pcap_resolver import (
    resolve_safe_pcap_path,
    compute_pcap_fingerprint,
    verify_pcap_unmodified,
    PcapSecurityError,
)


def clone_isolated_detector(base_detector: Detector) -> Detector:
    """Creates a fresh, isolated Detector with independent anomaly state."""
    detector = Detector(
        threshold=base_detector.threshold,
        anomaly_detector=AnomalyDetector(),
    )
    detector.bundle = base_detector.bundle
    detector.model_available = base_detector.model_available
    detector.fusion_engine = base_detector.fusion_engine.fresh()
    return detector


@dataclass
class ReplayExperiment:
    run_id: str
    pcap_path: str
    pcap_name: str
    pcap_sha256: str
    pcap_size_bytes: int
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
    telemetry_accounting: Dict[str, Any] = field(default_factory=dict)
    stability_verdict: str = "PENDING"  # STABLE, SENSITIVE, INCONCLUSIVE, PENDING
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "pcap_name": self.pcap_name,
            "pcap_sha256": self.pcap_sha256,
            "pcap_size_bytes": self.pcap_size_bytes,
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
            "telemetry_accounting": self.telemetry_accounting,
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
        """Safely enumerates available demo/fixture PCAPs from allowlisted roots."""
        results = []
        search_dirs = [self._artifacts_dir / "demo", Path("tests"), self._artifacts_dir]
        seen_names = set()

        for d in search_dirs:
            if d.exists() and d.is_dir():
                for p in d.glob("*.pcap"):
                    if p.name in seen_names:
                        continue
                    seen_names.add(p.name)
                    try:
                        size = p.stat().st_size
                        mtime = p.stat().st_mtime
                    except OSError:
                        continue

                    category = "CUSTOM"
                    if "-" in p.name:
                        category = p.name.split("-")[1]

                    results.append({
                        "filename": p.name,
                        "relative_path": str(p),
                        "size_bytes": size,
                        "modified_at": mtime,
                        "category": category,
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
        # Secure PCAP resolution
        resolved_path = resolve_safe_pcap_path(pcap_path)
        pcap_sha256, pcap_size = compute_pcap_fingerprint(resolved_path)

        run_id = f"replay-{uuid.uuid4().hex[:12]}"
        exp = ReplayExperiment(
            run_id=run_id,
            pcap_path=str(resolved_path),
            pcap_name=resolved_path.name,
            pcap_sha256=pcap_sha256,
            pcap_size_bytes=pcap_size,
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
        target_path = Path(exp.pcap_path)

        try:
            # Verify source non-mutation before starting
            if not verify_pcap_unmodified(target_path, exp.pcap_sha256):
                raise RuntimeError("Source PCAP modified prior to experiment execution.")

            # 1. Baseline Run (drop_rate=0.0) with isolated detector
            base_detector = clone_isolated_detector(self._detector)
            base_telemetry = ReplayTelemetry()
            base_windows = []

            for row in replay_stream(exp.pcap_path, drop_rate=0.0, seed=0, telemetry=base_telemetry):
                if cancel_event.is_set():
                    exp.status = "cancelled"
                    return
                pred = base_detector.predict(row)
                base_windows.append(pred)

            # 2. Perturbed Run with fresh isolated detector
            pert_detector = clone_isolated_detector(self._detector)
            pert_telemetry = ReplayTelemetry()
            pert_windows = []

            for row in replay_stream(
                exp.pcap_path,
                drop_rate=exp.drop_rate,
                seed=exp.seed,
                loss_mode=exp.loss_mode,
                burst_size=exp.burst_size,
                burst_interval=exp.burst_interval,
                drop_ip=exp.drop_ip,
                telemetry=pert_telemetry,
            ):
                if cancel_event.is_set():
                    exp.status = "cancelled"
                    return
                pred = pert_detector.predict(row)
                pert_windows.append(pred)

            # Verify source non-mutation after experiment
            if not verify_pcap_unmodified(target_path, exp.pcap_sha256):
                raise RuntimeError("Integrity violation: Source PCAP was modified during experiment.")

            # 3. Canonical Time-Window Alignment by window_key
            base_by_key = {w.get('window_key', f"{w['source']}@{round(float(w['timestamp']), 3)}"): w for w in base_windows}
            pert_by_key = {w.get('window_key', f"{w['source']}@{round(float(w['timestamp']), 3)}"): w for w in pert_windows}

            matched_keys = sorted(set(base_by_key.keys()) & set(pert_by_key.keys()))
            base_only_keys = sorted(set(base_by_key.keys()) - set(pert_by_key.keys()))
            pert_only_keys = sorted(set(pert_by_key.keys()) - set(base_by_key.keys()))

            # 4. Analyze summaries & feature shifts
            base_summary = self._summarize_windows(base_windows)
            pert_summary = self._summarize_windows(pert_windows)

            base_suspicious = [w for w in base_windows if w["decision"] == "SUSPECTED"]
            pert_suspicious = [w for w in pert_windows if w["decision"] == "SUSPECTED"]

            # Calculate decision shifts over matched and baseline-only windows
            decision_shifts = 0
            for k in matched_keys:
                b = base_by_key[k]
                p = pert_by_key[k]
                if b["decision"] == "SUSPECTED":
                    if p["decision"] != "SUSPECTED" or p["prediction"] != b["prediction"]:
                        decision_shifts += 1

            # Any baseline suspected window completely omitted in perturbed run is a decision shift
            for k in base_only_keys:
                if base_by_key[k]["decision"] == "SUSPECTED":
                    decision_shifts += 1

            # 5. Determine stability verdict
            if not base_suspicious:
                stability = "INCONCLUSIVE"  # Baseline had no threat to test
            elif decision_shifts > 0 or len(pert_suspicious) < len(base_suspicious):
                stability = "SENSITIVE"  # Decision changed or weakened under simulated loss
            else:
                stability = "STABLE"

            # 6. Build comparison metrics
            comparison = {
                "baseline_windows_count": len(base_windows),
                "perturbed_windows_count": len(pert_windows),
                "matched_windows_count": len(matched_keys),
                "baseline_only_windows_count": len(base_only_keys),
                "perturbed_only_windows_count": len(pert_only_keys),
                "baseline_suspicious_count": len(base_suspicious),
                "perturbed_suspicious_count": len(pert_suspicious),
                "decision_shifts": decision_shifts,
                "feature_shifts": self._compare_features(base_summary["mean_features"], pert_summary["mean_features"]),
                "fragility_status_comparison": {
                    "baseline": base_summary.get("fragility_statuses", {}),
                    "perturbed": pert_summary.get("fragility_statuses", {}),
                }
            }

            telemetry_accounting = {
                "source_packets": pert_telemetry.source_packets,
                "eligible_packets": pert_telemetry.eligible_packets,
                "omitted_packets": pert_telemetry.omitted_packets,
                "retained_packets": pert_telemetry.retained_packets,
                "nominal_drop_rate": pert_telemetry.nominal_drop_rate,
                "realized_omission_rate": pert_telemetry.realized_omission_rate,
                "eligible_omission_rate": pert_telemetry.eligible_omission_rate,
                "loss_mode": pert_telemetry.loss_mode,
                "seed": pert_telemetry.seed,
            }

            exp.baseline_summary = base_summary
            exp.perturbed_summary = pert_summary
            exp.comparison = comparison
            exp.telemetry_accounting = telemetry_accounting
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
