import unittest
from scapy.all import IP, TCP, UDP, ICMP
from backend.analyzer.packet_parser import parse_packet
from backend.analyzer.traffic_analyzer import TrafficAnalyzer


class AnalyzerTests(unittest.TestCase):
    def test_counters_rates_and_bounded_history(self):
        now = [0.0]
        analyzer = TrafficAnalyzer(recent_limit=3, clock=lambda: now[0])
        sizes = 0
        for count, layer in ((10, TCP), (5, UDP), (2, ICMP)):
            for _ in range(count):
                packet = parse_packet(IP()/layer())
                sizes += packet.packet_size
                analyzer.process(packet)
        now[0] = 2
        result = analyzer.snapshot()
        self.assertEqual(result['total_packets'], 17)
        self.assertEqual(result['total_bytes'], sizes)
        self.assertEqual(result['protocols'], {'TCP': 10, 'UDP': 5, 'ICMP': 2, 'OTHER': 0})
        self.assertEqual(result['packets_per_second'], 8.5)
        self.assertEqual(result['bytes_per_second'], sizes/2)
        self.assertEqual(len(result['recent']), 3)
        result['protocols']['TCP'] = 0
        self.assertEqual(analyzer.snapshot()['protocols']['TCP'], 10)

    def test_empty_snapshot(self):
        analyzer = TrafficAnalyzer(clock=lambda: 0)
        self.assertEqual(analyzer.snapshot()['packets_per_second'], 0)
