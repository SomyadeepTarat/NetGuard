from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import time

import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from backend.api.capture_manager import CaptureManager
from backend.services.source_selection import connected_interface, select_dataset
from backend.ml.features import FeatureExtractor
from backend.analyzer.packet_parser import parse_packet
from backend.ml.demo import build_demo_reference


@pytest.fixture
def manager():
    Path('artifacts').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir='artifacts') as directory:
        mgr = CaptureManager(db_path=str(Path(directory) / 'test.db'), artifacts_dir=directory)
        yield mgr
        mgr.close()


def test_connected_adapter_check_uses_local_state_without_probes():
    iface = SimpleNamespace(name='Wi-Fi', description='Wi-Fi', network_name='guid', ip='192.168.1.20', ips={})
    with patch('backend.services.source_selection.resolve_interface', return_value=iface), \
         patch('backend.services.source_selection.psutil.net_if_stats', return_value={'Wi-Fi': SimpleNamespace(isup=True)}), \
         patch('backend.services.source_selection.psutil.net_if_addrs', return_value={'Wi-Fi': [SimpleNamespace(address='192.168.1.20')]}):
        assert connected_interface('Wi-Fi') is iface
    with patch('backend.services.source_selection.resolve_interface', return_value=iface), \
         patch('backend.services.source_selection.psutil.net_if_stats', return_value={'Wi-Fi': SimpleNamespace(isup=False)}), \
         patch('backend.services.source_selection.psutil.net_if_addrs', return_value={}):
        with pytest.raises(RuntimeError):
            connected_interface('Wi-Fi')


def test_automatic_uses_live_when_backend_is_ready(manager):
    iface = SimpleNamespace(name='Wi-Fi')
    with patch('backend.api.session_manager.connected_interface', return_value=iface), \
         patch.object(manager, '_start_session') as start:
        manager._select_auto(None, None, 'tcp')
        start.assert_called_once_with('live', 'Wi-Fi', capture_filter='tcp')
        assert 'actual local interface' in manager._source_reason


def test_backend_failure_uses_dataset_and_reports_reason(manager):
    dataset = manager.artifacts_dir / 'dataset.pcap'
    with patch('backend.api.session_manager.connected_interface', return_value=SimpleNamespace(name='Wi-Fi')), \
         patch.object(manager, '_start_session', side_effect=[RuntimeError('Npcap missing'), None]) as start:
        manager._select_auto(None, dataset, None)
        assert start.call_args_list[1].kwargs['pcap_path'] == str(dataset)
        assert 'Npcap missing' in manager._source_reason
        assert 'offline' in manager._source_reason


def test_no_dataset_never_claims_real_dataset(manager):
    with patch('backend.api.session_manager.connected_interface', side_effect=RuntimeError('Disconnected')), \
         patch.object(manager, '_start_session') as start:
        manager._select_auto(None, None, None)
        start.assert_called_once_with('demo')
        assert 'synthetic' in manager._source_reason
    assert select_dataset(manager.artifacts_dir) is None


def test_dataset_clock_and_features_equal_canonical_replay(manager):
    packets = []
    for i in range(35):
        packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=5000, dport=443, flags='S')
        packet.time = 1700000000 + i * .1
        packets.append(packet)
    path = manager.artifacts_dir / 'clock.pcap'
    wrpcap(str(path), packets)
    canonical, expected = FeatureExtractor(), []
    for packet in packets:
        expected.extend(canonical.process(parse_packet(packet)))
    expected.extend(canonical.finish())
    with patch.object(manager, '_evaluate_window') as evaluate:
        manager._read_pcap(str(path))
        actual = [call.args[0] for call in evaluate.call_args_list]
    assert actual == expected
    assert all(row['features']['unique_ports'] == 1 for row in actual)
    assert manager.quality.get_quality_report()['packets_received'] == 35


def test_live_queue_backpressure_is_measured(manager):
    manager._queue.maxsize = 1
    packet = parse_packet(Ether() / IP() / TCP())
    manager.process(packet)
    manager.process(packet)
    assert manager.quality._queue_drops == 1


def test_fusion_evidence_survives_repository_round_trip(manager):
    key = manager.repository.save_incident({'source_ip': '10.0.0.1', 'protocol': 'TCP',
        'detector_class': 'ANOMALOUS_UNKNOWN_PATTERN', 'research_fusion': {'p_value': .02, 'visibility': {'status': 'SENSITIVE'}}})
    record = manager.repository.get_incident_by_id(key)
    assert record['research_fusion']['visibility']['status'] == 'SENSITIVE'


def test_manual_dataset_session_reaches_eof_with_original_clock(manager):
    packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP()
    packet.time = 1700000000
    path = manager.artifacts_dir / 'session.pcap'
    wrpcap(str(path), [packet])
    manager.start_capture(mode='pcap', pcap_path=str(path))
    manager._worker_thread.join(timeout=3)
    status = manager.get_status()
    assert status['mode'] == 'PCAP' and not status['running']
    assert status['total_packets'] == 1 and status['error'] is None
    assert manager.detection_status()['recent_windows'][0]['timestamp'] == 1700000001


def test_live_packets_enter_the_same_pipeline(manager):
    class CaptureDouble:
        def __init__(self, sink, **kwargs):
            self.sink = sink

        def start(self):
            packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP()
            packet.time = time.time()
            self.sink.process(parse_packet(packet))

        def stop(self):
            pass

    with patch('backend.api.session_manager.resolve_interface', return_value=SimpleNamespace(name='Wi-Fi')), \
         patch('backend.api.session_manager.PacketCapture', CaptureDouble):
        manager.start_capture(mode='live')
        deadline = time.monotonic() + 2
        while manager.analyzer._packets == 0 and time.monotonic() < deadline:
            time.sleep(.01)
        assert manager.get_status()['mode'] == 'LIVE'
        assert manager.quality.get_quality_report()['packets_received'] == 1
        assert manager.analyzer.snapshot()['total_packets'] == 1
        manager.stop_capture()


def test_failed_driver_retry_does_not_reset_running_dataset(manager):
    manager._mode, manager._running = 'PCAP', True
    with patch.object(manager, '_auto_stop') as stop, \
         patch('backend.api.session_manager.connected_interface', return_value=SimpleNamespace(name='Wi-Fi')), \
         patch('backend.api.session_manager.PacketCapture') as capture, \
         patch.object(manager, '_stop_session') as end:
        stop.wait.side_effect = [False, True]
        stop.is_set.return_value = False
        capture.return_value.start.side_effect = RuntimeError('Npcap unavailable')
        manager._monitor_auto(None, None, None)
        end.assert_not_called()
        assert manager._running


def test_live_disconnect_requests_fallback(manager):
    manager._mode, manager._running = 'LIVE', True
    with patch.object(manager, '_auto_stop') as stop, \
         patch('backend.api.session_manager.connected_interface', side_effect=RuntimeError('Link down')), \
         patch.object(manager, '_stop_session') as end, patch.object(manager, '_select_auto') as select:
        stop.wait.side_effect = [False, True]
        stop.is_set.return_value = False
        manager._monitor_auto(None, None, None)
        end.assert_called_once()
        select.assert_called_once()


def test_demo_reference_uses_original_train_and_validation_pcaps_only(manager):
    for split, offset in [('train', 0), ('validation', 1000), ('test', 2000)]:
        packets = []
        for i in range(40):
            packet = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(dport=443)
            packet.time = 1700000000 + offset + i
            packets.append(packet)
        wrpcap(str(manager.artifacts_dir / f'{split}-BENIGN-0.pcap'), packets)
    engine = build_demo_reference(manager.artifacts_dir)
    assert engine.model is not None
    assert len(engine.reference) == 48
    assert all(row['timestamp'] < 1700002000 for row in engine.reference)
    assert engine.reference_scope == 'synthetic-demo-overlapping-reference'
    manager._shutdown.set()
    assert build_demo_reference(manager.artifacts_dir, manager._shutdown) is None


def test_connected_backend_promotes_offline_source(manager):
    manager._mode, manager._running = 'PCAP', True
    with patch.object(manager, '_auto_stop') as stop, \
         patch('backend.api.session_manager.connected_interface', return_value=SimpleNamespace(name='Wi-Fi')), \
         patch('backend.api.session_manager.PacketCapture'), \
         patch.object(manager, '_stop_session') as end, patch.object(manager, '_select_auto') as select:
        stop.wait.side_effect = [False, True]
        stop.is_set.return_value = False
        manager._monitor_auto(None, None, None)
        end.assert_called_once()
        select.assert_called_once()
