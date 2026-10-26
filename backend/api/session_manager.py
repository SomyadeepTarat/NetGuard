"""Real packet-window ingestion with bounded capture queues and automatic sources."""
from collections import deque
from pathlib import Path
from queue import Queue, Empty, Full
import threading
import time
import json
import os
from scapy.utils import PcapReader
from backend.analyzer.packet_parser import parse_packet
from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.analyzer.flow_engine import FlowEngine
from backend.capture.packet_capture import PacketCapture, resolve_interface
from backend.ml.features import FeatureExtractor
from backend.ml.detector import Detector
from backend.ml.evidence_fusion import EvidenceFusionEngine, FusionConfig
from backend.services.capture_quality import CaptureQualityService
from backend.services.source_selection import connected_interface, select_dataset
from backend.services.pcap_resolver import resolve_safe_pcap_path
from backend.storage.repository import IncidentRepository
from backend.services.replay_lab import ReplayLabService, clone_isolated_detector
from backend.ml.robustness_sweep import RobustnessSweepEngine
from backend.services.observation_planner import PassiveNextObservationPlanner
from backend.storage.evidence_lineage import EvidenceLineageService


class CaptureManager:
    def __init__(self, model_path='artifacts/netguard.joblib', db_path='artifacts/netguard_incidents.db', artifacts_dir='artifacts'):
        self.artifacts_dir = Path(artifacts_dir)
        self.flow_engine = FlowEngine(max_flows=10000)
        self.analyzer = TrafficAnalyzer(recent_limit=30, flow_engine=self.flow_engine)
        self.quality = CaptureQualityService(mode='DEMO', interface='idle')
        self.repository = IncidentRepository(db_path)
        candidates = [model_path, 'artifacts/netguard.joblib', 'artifacts/demo/model.joblib']
        self.detector = Detector(next((p for p in candidates if p and Path(p).exists()), None))
        self._reference_bundle = None
        reference_path = os.environ.get('NETGUARD_FUSION_REFERENCE')
        if reference_path:
            self._reference_bundle = json.loads(Path(reference_path).read_text())
        self.anomaly_detector = self.detector.anomaly_detector
        self.extractor = FeatureExtractor()
        self.replay_lab = ReplayLabService(self.detector, artifacts_dir)
        self.robustness_sweep = RobustnessSweepEngine(self.detector, artifacts_dir)
        self.lineage_service = EvidenceLineageService(db_path)
        self.observation_planner = PassiveNextObservationPlanner()
        self._lock, self._pipeline_lock = threading.RLock(), threading.RLock()
        self._running = False
        self._mode, self._interface_name = 'DEMO', 'idle'
        self._started_at, self._stopped_at = time.time(), None
        self._capture_instance, self._worker_thread = None, None
        self._stop_event, self._shutdown, self._auto_stop = (threading.Event() for _ in range(3))
        self._auto_enabled, self._auto_thread = False, None
        self._source_reason, self._error = 'No ingestion started', None
        self._timeseries, self._recent_detections = deque(maxlen=300), deque(maxlen=20)
        self._last_alert_time = {}
        self._queue = Queue(maxsize=4096)
        self._ticker_thread = threading.Thread(target=self._run_ticker, daemon=True)
        self._ticker_thread.start()

    @property
    def is_running(self):
        return self._running

    @property
    def mode(self):
        return self._mode

    @property
    def interface(self):
        return self._interface_name

    def get_status(self):
        with self._pipeline_lock, self._lock:
            snap = self.analyzer.snapshot()
            _, count = self.repository.get_incidents(limit=1)
            metrics = snap.get('flow_metrics', {})
            end = self._stopped_at if self._stopped_at is not None else time.time()
            return {
                'running': self._running, 'mode': self._mode, 'interface': self._interface_name,
                'uptime': max(0, end - self._started_at),
                **{k: snap[k] for k in ('total_packets', 'total_bytes', 'protocols', 'extended_protocols', 'packets_per_second', 'bytes_per_second')},
                **{k: metrics.get(k, 0) for k in ('active_hosts', 'active_flows', 'total_flows', 'total_hosts')},
                'rates': metrics.get('rates', {}), 'capture_quality': self.quality.get_quality_report(),
                'model_available': self.detector.model_available,
                'model_scope': self.detector.bundle.get('scope', 'local-artifact') if self.detector.bundle else 'rules + experimental evidence fusion',
                'recent_alerts_count': count, 'error': self._error,
                'source_selection': {'automatic': self._auto_enabled, 'reason': self._source_reason, 'recheck_seconds': 5},
                'research_fusion': self.detector.fusion_engine.status(),
            }

    def get_timeseries(self):
        with self._lock:
            return list(self._timeseries)

    def detection_status(self):
        with self._pipeline_lock:
            return {**self.detector.fusion_engine.status(), 'recent_windows': list(self._recent_detections)}

    def start_capture(self, mode='auto', interface=None, pcap_path=None, capture_filter=None):
        if mode not in ('auto', 'demo', 'pcap', 'live'):
            raise ValueError('Unknown ingestion mode')
        with self._lock:
            if self._running or self._auto_enabled:
                raise RuntimeError('Capture is already running. Stop the active session first.')
        if mode != 'auto':
            self._source_reason = 'Manually selected ingestion source'
            self._start_session(mode, interface, pcap_path, capture_filter)
            return
        dataset = select_dataset(self.artifacts_dir, pcap_path)
        self._auto_stop.clear()
        self._auto_enabled = True
        try:
            self._select_auto(interface, dataset, capture_filter)
        except Exception:
            self._auto_enabled = False
            raise
        self._auto_thread = threading.Thread(target=self._monitor_auto, args=(interface, dataset, capture_filter), daemon=True)
        self._auto_thread.start()

    def _select_auto(self, interface, dataset, capture_filter):
        try:
            iface = connected_interface(interface)
            self._start_session('live', iface.name, capture_filter=capture_filter)
            self._source_reason = 'Active adapter and capture backend are ready; observing actual local interface traffic'
            return
        except Exception as error:
            reason = f'Live capture unavailable: {error}'
            self._stop_session()
        if dataset:
            self._start_session('pcap', pcap_path=str(dataset))
            self._source_reason = f'{reason}. Using dataset {dataset.name} (offline)'
        else:
            self._start_session('demo')
            self._source_reason = f'{reason}. No dataset PCAP configured; using explicitly labeled synthetic fixtures'

    def _monitor_auto(self, interface, dataset, capture_filter):
        while not self._auto_stop.wait(5):
            try:
                if self._mode == 'LIVE':
                    connected_interface(self._interface_name)
                    if not self._capture_instance or not self._capture_instance.check() or not self._running:
                        raise RuntimeError('Capture backend or analysis worker stopped')
                    continue
                try:
                    iface = connected_interface(interface)
                except Exception:
                    if self._running:
                        continue
                else:
                    if self._running:
                        # A connected adapter may still lack Npcap/permissions.
                        # Verify the backend first so a failed retry does not
                        # repeatedly reset a long-running offline session.
                        preview = PacketCapture(_ReadinessSink(), interface=iface.name, capture_filter=capture_filter)
                        try:
                            preview.start()
                        except Exception as error:
                            self._source_reason = f'Live retry unavailable: {error}. Continuing {self._mode} source {self._interface_name}'
                            continue
                        finally:
                            try:
                                preview.stop()
                            except Exception:
                                pass
                self._stop_session()
                if not self._auto_stop.is_set():
                    self._select_auto(interface, dataset, capture_filter)
            except Exception as error:
                if not self._auto_stop.is_set():
                    try:
                        self._stop_session()
                        self._select_auto(interface, dataset, capture_filter)
                    except Exception as failure:
                        self._error = f'{error}; fallback failed: {failure}'

    def _start_session(self, mode, interface=None, pcap_path=None, capture_filter=None):
        target = resolve_safe_pcap_path(pcap_path, additional_roots=[self.artifacts_dir]) if mode == 'pcap' else None
        resolved = resolve_interface(interface) if mode == 'live' else None
        with self._pipeline_lock, self._lock:
            self._stop_event = threading.Event()
            self._queue = Queue(maxsize=4096)
            self.analyzer.reset()
            self.extractor = FeatureExtractor()
            self.detector = clone_isolated_detector(self.detector)
            if self.detector.fusion_engine.reference_scope.startswith('automatic'):
                self.detector.fusion_engine = EvidenceFusionEngine(self.detector.fusion_engine.config)
            if mode == 'live' and 'synthetic' in self.detector.fusion_engine.reference_scope.lower():
                self.detector.fusion_engine = EvidenceFusionEngine()
            if self._reference_bundle:
                bundle = self._reference_bundle
                if mode == 'live' and 'synthetic' in bundle['scope'].lower():
                    self.detector.fusion_engine = EvidenceFusionEngine()
                else:
                    engine = EvidenceFusionEngine(FusionConfig(**bundle['config']))
                    engine.fit_reference(bundle['rows'], bundle['scope'])
                    self.detector.fusion_engine = engine
            self.anomaly_detector = self.detector.anomaly_detector
            self.replay_lab.set_detector(self.detector)
            self.robustness_sweep.set_detector(self.detector)
            self._timeseries.clear()
            self._recent_detections.clear()
            self._last_alert_time.clear()
            self._started_at, self._stopped_at, self._error = time.time(), None, None
            self._mode = mode.upper()
            self._interface_name = resolved.name if resolved else target.name if target else 'synthetic-demo'
            self.quality = CaptureQualityService('PCAP_REPLAY' if target else self._mode, self._interface_name)
            self._running = True
        if mode == 'live':
            self._capture_instance = PacketCapture(self, interface=resolved.name, capture_filter=capture_filter)
            try:
                self._capture_instance.start()
            except Exception:
                self._stop_session()
                raise
            worker, args = self._drain_live, ()
        else:
            worker = self._run_pcap_playback if target else self._run_demo_loop
            args = (str(target),) if target else ()
        self._worker_thread = threading.Thread(target=worker, args=args, daemon=True)
        self._worker_thread.start()

    def _stop_session(self):
        self._stop_event.set()
        capture, self._capture_instance = self._capture_instance, None
        if capture:
            try:
                capture.stop()
            except Exception as error:
                self._error = str(error)
        worker = self._worker_thread
        if worker and worker is not threading.current_thread() and worker.is_alive():
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError('Previous ingestion worker did not stop; refusing to mix sessions')
        with self._lock:
            self._running = False
            if self._stopped_at is None:
                self._stopped_at = time.time()

    def stop_capture(self):
        self._auto_stop.set()
        self._auto_enabled = False
        if self._auto_thread and self._auto_thread is not threading.current_thread():
            self._auto_thread.join(timeout=10)
            if self._auto_thread.is_alive():
                raise RuntimeError('Source supervisor has not stopped yet')
        self._stop_session()

    def close(self):
        self.stop_capture()
        self._shutdown.set()
        self._ticker_thread.join(timeout=2)

    def process(self, packet):
        """Fast sniffer callback: queue metadata; inference runs on a worker."""
        if not self._stop_event.is_set():
            try:
                self._queue.put_nowait(packet)
            except Full:
                self.quality.record_queue_drop()

    def _drain_live(self):
        try:
            while not self._stop_event.is_set():
                try:
                    self._process_parsed(self._queue.get(timeout=0.1))
                except Empty:
                    with self._pipeline_lock:
                        for row in self.extractor.advance(time.time()):
                            self._evaluate_window(row)
        except Exception as error:
            self._error = f'Analysis worker failed: {error}'
        finally:
            self._running = False

    def _ingest_packet(self, packet):
        self._process_parsed(parse_packet(packet))

    def _process_parsed(self, packet):
        with self._pipeline_lock:
            self.analyzer.process(packet)
            before = self.extractor.late_packets
            rows = self.extractor.process(packet)
            self.quality.record_packet(parser_error=bool(packet.parser_error), out_of_order=self.extractor.late_packets > before)
            self.quality._flow_evictions = self.extractor.evictions + self.flow_engine._flow_evictions
            for row in rows:
                self._evaluate_window(row)

    def _evaluate_window(self, row):
        q = self.quality.get_quality_report()
        row['quality'].update(queue_drops=self.quality._queue_drops, parser_errors=self.quality._parser_errors)
        pred = self.detector.predict(row)
        self._recent_detections.append({'timestamp': row['timestamp'], 'source': row['source'],
            'prediction': pred['prediction'], 'decision': pred['decision'], 'research_fusion': pred['research_fusion']})
        if pred['decision'] == 'BENIGN' or pred['prediction'] == 'BENIGN':
            return
        key = (row['source'], pred['prediction'])
        if row['timestamp'] - self._last_alert_time.get(key, -float('inf')) < 10:
            return
        self._last_alert_time[key] = row['timestamp']
        incident = {
            'timestamp': row['timestamp'], 'source_ip': row['source'], **row.get('traffic_context', {}),
            'detector_class': pred['prediction'], 'detector_score': pred['score'] if pred['model_available'] else None,
            'is_calibrated': False, 'decision': pred['decision'], 'model_scope': pred['model_scope'],
            'rule_triggers': [r for r in pred['detailed_rules'] if r['triggered']], 'anomaly': pred['anomaly'],
            'capture_quality': q, 'evidence': pred['evidence'], 'fragility': pred.get('fragility', {}),
            'research_fusion': pred['research_fusion'], 'provenance': f'{self._mode}:{self._interface_name}',
        }
        incident_id = self.repository.save_incident(incident)
        try:
            self.lineage_service.record_event('INCIDENT_RECORDED', {
                'alert_id': incident_id, 'detector_class': incident['detector_class'], 'decision': incident['decision'],
                'source_mode': self._mode, 'fusion_version': self.detector.fusion_engine.version,
                'reference_sha256': pred['research_fusion'].get('reference_sha256'),
            })
        except Exception as error:
            self._error = f'Incident saved; lineage recording failed: {error}'

    def _read_pcap(self, path, synthetic=False):
        """Keep original PCAP timestamps and feature timing; pace independently."""
        with PcapReader(path) as reader:
            previous = None
            for raw in reader:
                t = float(raw.time)
                delay = 0 if previous is None else min(0.05, max(0, (t - previous) * 0.1))
                if self._stop_event.wait(0.005 if synthetic else delay):
                    return
                self._ingest_packet(raw)
                previous = t
        with self._pipeline_lock:
            for row in self.extractor.finish():
                self._evaluate_window(row)

    def _run_pcap_playback(self, path):
        try:
            self._read_pcap(path)
        except Exception as error:
            self._error = str(error)
        finally:
            self._running, self._stopped_at = False, time.time()

    def _run_demo_loop(self):
        try:
            demo_dir = self.artifacts_dir / 'demo'
            pcaps = sorted(demo_dir.glob('*.pcap'))
            if not pcaps:
                from backend.ml.demo import generate
                generate(str(demo_dir), sessions=4, stop_event=self._stop_event)
                pcaps = sorted(demo_dir.glob('*.pcap'))
            if not self._reference_bundle:
                from backend.ml.demo import build_demo_reference
                reference_engine = build_demo_reference(demo_dir, self._stop_event)
                if reference_engine is not None:
                    with self._pipeline_lock:
                        self.detector.fusion_engine = reference_engine
            while not self._stop_event.is_set():
                for path in pcaps:
                    if self._stop_event.is_set():
                        return
                    with self._pipeline_lock:
                        # Each fixture is a distinct capture with its own clock.
                        self.extractor = FeatureExtractor()
                        self.detector = clone_isolated_detector(self.detector)
                        if self.detector.fusion_engine.reference_scope.startswith('automatic'):
                            self.detector.fusion_engine = EvidenceFusionEngine(self.detector.fusion_engine.config)
                        self.anomaly_detector = self.detector.anomaly_detector
                        self._last_alert_time.clear()
                    self._read_pcap(str(path), synthetic=True)
                if self._stop_event.wait(0.5):
                    break
        except Exception as error:
            self._error = str(error)
        finally:
            self._running, self._stopped_at = False, time.time()

    def _run_ticker(self):
        last_time, last_packets, last_bytes = time.time(), 0, 0
        while not self._shutdown.wait(1):
            now = time.time()
            with self._lock:
                snap = self.analyzer.snapshot()
                dt = max(0.1, now - last_time)
                self._timeseries.append({'timestamp': now, 'iso_time': time.strftime('%H:%M:%S', time.localtime(now)),
                    'packets_per_sec': max(0, (snap['total_packets'] - last_packets) / dt),
                    'bytes_per_sec': max(0, (snap['total_bytes'] - last_bytes) / dt)})
                last_time, last_packets, last_bytes = now, snap['total_packets'], snap['total_bytes']


class _ReadinessSink:
    """Discard passive pre-session readiness frames; never mix them into a dataset."""
    def process(self, packet):
        pass
