import tempfile
import time
import unittest
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap
from backend.capture.packet_capture import PacketCapture, resolve_interface
from backend.analyzer.traffic_analyzer import TrafficAnalyzer


class CaptureTests(unittest.TestCase):
    def test_pcap_capture_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'traffic.pcap'
            wrpcap(str(path), [
                Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP()/TCP(),
                Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP()/UDP(),
                Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP()/ICMP()
            ])
            analyzer = TrafficAnalyzer()
            capture = PacketCapture(analyzer, pcap=str(path))
            capture.start()
            capture.sniffer.join(timeout=5)
            self.assertFalse(capture.check())
            capture.stop()
            self.assertEqual(analyzer.snapshot()['total_packets'], 3)
            self.assertEqual(analyzer.snapshot()['protocols'], {'TCP': 1, 'UDP': 1, 'ICMP': 1, 'OTHER': 0})

    def test_invalid_interface(self):
        with self.assertRaises(ValueError):
            resolve_interface('netguard-interface-does-not-exist')
