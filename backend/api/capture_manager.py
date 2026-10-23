"""Central Capture and State Orchestrator for the NetGuard Observatory.

Coordinates packet capture, flow analysis, ML scoring, quality telemetry,
incident storage, and real-time SSE/WebSocket fan-out.
"""
import asyncio
from collections import deque
import json
from pathlib import Path
import threading
import time
from typing import Any, AsyncGenerator, Dict, List, Optional
from scapy.utils import PcapReader
from backend.analyzer.packet_parser import parse_packet
from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.analyzer.flow_engine import FlowEngine
from backend.capture.packet_capture import PacketCapture, list_interfaces, resolve_interface
from backend.ml.detector import Detector
from backend.ml.anomaly import AnomalyDetector
from backend.services.capture_quality import CaptureQualityService
from backend.storage.repository import IncidentRepository
from backend.services.replay_lab import ReplayLabService
from backend.ml.robustness_sweep import RobustnessSweepEngine
from backend.services.observation_planner import PassiveNextObservationPlanner
from backend.storage.evidence_lineage import EvidenceLineageService


class CaptureManager:
    def __init__(
        self,
        model_path: str = "artifacts/netguard.joblib",
        db_path: str = "artifacts/netguard_incidents.db",
        artifacts_dir: str = "artifacts"
    ):
        self.artifacts_dir = Path(artifacts_dir)
        self.flow_engine = FlowEngine(max_flows=10000)
        self.analyzer = TrafficAnalyzer(recent_limit=30, flow_engine=self.flow_engine)
        self.quality = CaptureQualityService(mode="DEMO", interface="synthetic-demo")
        self.repository = IncidentRepository(db_path=db_path)
        
        # Detector & Anomaly initialization
        self.anomaly_detector = AnomalyDetector(min_warmup_windows=10)
        resolved_model = None
        for candidate in [model_path, "artifacts/netguard.joblib", "artifacts/demo/model.joblib"]:
            if candidate and Path(candidate).exists():
                resolved_model = candidate
                break

        self.detector = Detector(
            model_path=resolved_model,
            anomaly_detector=self.anomaly_detector
        )
        self.replay_lab = ReplayLabService(detector=self.detector, artifacts_dir=artifacts_dir)
        self.robustness_sweep = RobustnessSweepEngine(detector=self.detector, artifacts_dir=artifacts_dir)
        self.lineage_service = EvidenceLineageService(db_path=db_path)
        self.observation_planner = PassiveNextObservationPlanner()

        # State & locks
        self._lock = threading.Lock()
        self._running = False
        self._mode = "DEMO"  # DEMO, LIVE, PCAP
        self._interface_name = "synthetic-demo"
        self._started_at = time.time()
        self._stopped_at: Optional[float] = None
        self._capture_instance: Optional[PacketCapture] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._error: Optional[str] = None

        # Timeseries buffer: 1-second rolling snapshots (last 300 seconds = 5 minutes)
        self._timeseries: deque = deque(maxlen=300)
        self._last_sec_packets = 0
        self._last_sec_bytes = 0

        # Broadcast queues for SSE and WebSockets
        self._listeners: List[asyncio.Queue] = []
        self._last_alert_time: Dict[tuple, float] = {}

        # Background metrics ticker thread
        self._ticker_thread = threading.Thread(target=self._run_ticker, daemon=True)
        self._ticker_thread.start()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    @property
    def interface(self) -> str:
        with self._lock:
            return self._interface_name

    def get_status(self) -> dict:
        with self._lock:
            snap = self.analyzer.snapshot()
            q_report = self.quality.get_quality_report()
            _, total_alerts = self.repository.get_incidents(limit=1)

            uptime = (self._stopped_at - self._started_at) if (not self._running and self._stopped_at is not None) else max(0.0, time.time() - self._started_at)

            return {
                "running": self._running,
                "mode": self._mode,
                "interface": self._interface_name,
                "uptime": max(0.0, uptime),
                "total_packets": snap["total_packets"],
                "total_bytes": snap["total_bytes"],
                "protocols": snap["protocols"],
                "extended_protocols": snap["extended_protocols"],
                "packets_per_second": snap["packets_per_second"],
                "bytes_per_second": snap["bytes_per_second"],
                "rates": snap.get("flow_metrics", {}).get("rates", {}),
                "active_hosts": snap.get("flow_metrics", {}).get("active_hosts", 0),
                "active_flows": snap.get("flow_metrics", {}).get("active_flows", 0),
                "total_flows": snap.get("flow_metrics", {}).get("total_flows", 0),
                "total_hosts": snap.get("flow_metrics", {}).get("total_hosts", 0),
                "capture_quality": q_report,
                "model_available": self.detector.model_available,
                "model_scope": getattr(self.detector, 'bundle', {}).get('scope', 'unavailable') if self.detector.bundle else "rule-only fallback",
                "recent_alerts_count": total_alerts,
                "error": self._error,
            }

    def get_timeseries(self) -> List[dict]:
        with self._lock:
            return list(self._timeseries)

    def start_capture(
        self,
        mode: str = "demo",
        interface: Optional[str] = None,
        pcap_path: Optional[str] = None,
        capture_filter: Optional[str] = None
    ) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError("Capture is already running. Stop the active session first.")
            self._error = None
            self._stop_event.clear()
            self.analyzer.reset()
            self._timeseries.clear()
            self._last_sec_packets = 0
            self._last_sec_bytes = 0
            self._started_at = time.time()
            self._stopped_at = None

            if mode == "demo":
                self._mode = "DEMO"
                self._interface_name = "synthetic-demo"
                self.quality.set_mode("DEMO", "synthetic-demo")
                self._worker_thread = threading.Thread(target=self._run_demo_loop, daemon=True)
                self._running = True
                self._worker_thread.start()

            elif mode == "pcap":
                if not pcap_path:
                    raise ValueError("pcap_path is required for PCAP replay mode.")
                target = Path(pcap_path).resolve()
                if not target.exists():
                    raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
                self._mode = "PCAP"
                self._interface_name = target.name
                self.quality.set_mode("PCAP_REPLAY", target.name)
                self._worker_thread = threading.Thread(target=self._run_pcap_playback, args=(str(target),), daemon=True)
                self._running = True
                self._started_at = time.time()
                self._worker_thread.start()

            elif mode == "live":
                resolved = resolve_interface(interface)
                self._mode = "LIVE"
                self._interface_name = resolved.name
                self.quality.set_mode("LIVE", resolved.name)
                try:
                    self._capture_instance = PacketCapture(
                        self.analyzer,
                        interface=resolved.name,
                        capture_filter=capture_filter
                    )
                    self._capture_instance.start()
                    self._running = True
                    self._started_at = time.time()
                except Exception as error:
                    self._running = False
                    self._error = str(error)
                    raise RuntimeError(f"Live capture failed to start: {error}. Check administrator/root privileges.")

    def stop_capture(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stopped_at = time.time()
            self._stop_event.set()

            if self._capture_instance is not None:
                try:
                    self._capture_instance.stop()
                except Exception:
                    pass
                self._capture_instance = None

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=3.0)

    def _ingest_packet(self, packet) -> None:
        info = parse_packet(packet)
        self.analyzer.process(info)
        self.quality.record_packet(parser_error=bool(info.parser_error))

    def _run_pcap_playback(self, path: str) -> None:
        try:
            with PcapReader(path) as reader:
                last_time = None
                for raw in reader:
                    if self._stop_event.is_set():
                        break
                    # Pacing
                    pkt_time = float(getattr(raw, "time", 0.0))
                    if last_time is not None:
                        gap = min(0.05, max(0.001, (pkt_time - last_time) * 0.1))
                        time.sleep(gap)
                    last_time = pkt_time
                    raw.time = time.time()
                    self._ingest_packet(raw)
        except Exception as error:
            self._error = str(error)
        finally:
            with self._lock:
                self._running = False
                self._stopped_at = time.time()

    def _run_demo_loop(self) -> None:
        """Plays through generated demo PCAPs in a continuous deterministic loop."""
        demo_dir = self.artifacts_dir / "demo"
        # Find demo pcaps or generate them if absent
        pcaps = list(demo_dir.glob("*.pcap")) if demo_dir.exists() else []
        if not pcaps:
            from backend.ml.demo import generate
            generate(str(demo_dir), sessions=4)
            pcaps = list(demo_dir.glob("*.pcap"))

        while not self._stop_event.is_set():
            for pcap in pcaps:
                if self._stop_event.is_set():
                    break
                try:
                    with PcapReader(str(pcap)) as reader:
                        for raw in reader:
                            if self._stop_event.is_set():
                                break
                            time.sleep(0.005)  # smooth pacing ~ 200 pkts/s
                            raw.time = time.time()
                            self._ingest_packet(raw)
                except Exception:
                    pass
                time.sleep(0.5)

    def _run_ticker(self) -> None:
        """Computes 1-second timeseries points and evaluates rolling alerts."""
        last_check = time.time()
        while True:
            time.sleep(1.0)
            now = time.time()
            with self._lock:
                total_pkts = self.analyzer._packets
                total_bytes = self.analyzer._bytes
                dt = max(0.1, now - last_check)
                pkts_rate = round((total_pkts - self._last_sec_packets) / dt, 2)
                bytes_rate = round((total_bytes - self._last_sec_bytes) / dt, 2)
                self._last_sec_packets = total_pkts
                self._last_sec_bytes = total_bytes
                last_check = now

                point = {
                    "timestamp": now,
                    "iso_time": time.strftime("%H:%M:%S", time.localtime(now)),
                    "packets_per_sec": max(0.0, pkts_rate),
                    "bytes_per_sec": max(0.0, bytes_rate),
                }
                self._timeseries.append(point)

            # Check if active flows warrant automated incident evaluation
            self._evaluate_active_flow_threats(now)

    def _evaluate_active_flow_threats(self, current_time: float) -> None:
        flows, _ = self.flow_engine.get_flows(limit=10)
        q_report = self.quality.get_quality_report()

        for f in flows:
            # Check for high SYN rates or port scan indicators
            is_suspicious = False
            cls = "BENIGN"
            score = 0.0

            if f["packet_count"] > 15 and f["protocol"] == "TCP":
                # Synthesize feature row for detector
                feat = {
                    "packets": f["packet_count"],
                    "bytes_per_second": f["byte_count"] / max(f["duration"], 0.1),
                    "unique_ports": 20 if (f["forward_packets"] > 10 and not f["handshake"]["completed"]) else 1,
                    "unique_hosts": 1,
                    "syn_rate": f["forward_packets"] / max(f["duration"], 0.1) if f["handshake"]["syn_observed"] else 0.0,
                    "rst_fraction": 0.5 if f["handshake"]["reset_observed"] else 0.0,
                    "response_fraction": f["reverse_packets"] / max(f["packet_count"], 1),
                    "mean_size": f["byte_count"] / max(f["packet_count"], 1),
                    "udp_fraction": 0.0,
                    "icmp_fraction": 0.0,
                    "mean_gap": max(0.001, f["duration"] / max(f["packet_count"] - 1, 1)),
                    "completed_fraction": 1.0 if f["handshake"]["completed"] else 0.0,
                }
                row = {
                    "timestamp": current_time,
                    "source": f["client_ip"],
                    "features": feat,
                    "quality": {
                        "state_evictions": q_report["indicators"][3]["value"] or 0,
                        "late_packets": q_report["indicators"][4]["value"] or 0,
                        "queue_drops": q_report["indicators"][2]["value"] or 0,
                    },
                    "handshake_context": {
                        "syn_flows": 1 if f["handshake"]["syn_observed"] else 0,
                        "completed_flows": 1 if f["handshake"]["completed"] else 0,
                        "repairable_flows": 1 if (f["handshake"]["syn_observed"] and not f["handshake"]["completed"]) else 0,
                        "window_seconds": 5.0,
                    }
                }
                pred = self.detector.predict(row)
                if pred["decision"] in ("SUSPECTED", "UNCERTAIN") and pred["prediction"] != "BENIGN":
                    key = (f["client_ip"], pred["prediction"])
                    # 10s cooldown
                    if current_time - self._last_alert_time.get(key, 0.0) >= 10.0:
                        self._last_alert_time[key] = current_time
                        incident = {
                            "source_ip": f["client_ip"],
                            "destination_ip": f["server_ip"],
                            "protocol": f["protocol"],
                            "detector_class": pred["prediction"],
                            "detector_score": pred["score"],
                            "is_calibrated": False,
                            "decision": pred["decision"],
                            "model_scope": pred["model_scope"],
                            "rule_triggers": [r for r in pred["detailed_rules"] if r["triggered"]],
                            "anomaly": pred["anomaly"],
                            "capture_quality": q_report,
                            "evidence": pred["evidence"],
                            "fragility": pred.get("fragility", {}),
                            "provenance": self._interface_name
                        }
                        incident_id = self.repository.save_incident(incident)
                        try:
                            self.lineage_service.record_event(
                                event_type="INCIDENT_RECORDED",
                                manifest_data={
                                    "alert_id": incident_id,
                                    "detector_class": incident.get("detector_class"),
                                    "decision": incident.get("decision"),
                                    "source_ip": incident.get("source_ip"),
                                    "destination_ip": incident.get("destination_ip"),
                                    "score": incident.get("detector_score"),
                                    "quality_status": q_report.get("overall_status"),
                                },
                                parent_id=None,
                            )
                        except Exception:
                            pass
