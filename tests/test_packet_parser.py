import unittest
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw
from backend.analyzer.packet_parser import parse_packet


class ParserTests(unittest.TestCase):
    def test_tcp_metadata(self):
        raw = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP(src='192.168.1.5', dst='192.168.1.10')/TCP(sport=5000, dport=80, flags='SA')/Raw(b'x'*100)
        raw.time = 1700000000
        result = parse_packet(raw)
        self.assertEqual((result.source_ip, result.destination_ip), ('192.168.1.5', '192.168.1.10'))
        self.assertEqual((result.protocol, result.source_port, result.destination_port), ('TCP', 5000, 80))
        self.assertEqual(result.tcp_flags, ('SYN', 'ACK'))
        self.assertEqual(result.packet_size, len(bytes(raw)))
        self.assertEqual(result.timestamp.timestamp(), 1700000000)

    def test_udp(self):
        result = parse_packet(IP()/UDP(sport=53000, dport=53))
        self.assertEqual((result.protocol, result.source_port, result.destination_port), ('UDP', 53000, 53))
        self.assertEqual(result.tcp_flags, ())

    def test_icmp(self):
        result = parse_packet(IP()/ICMP())
        self.assertEqual(result.protocol, 'ICMP')
        self.assertIsNone(result.source_port)
        self.assertIsNone(result.destination_port)

    def test_unsupported_and_malformed(self):
        for raw in (Ether()/ARP(), IP(proto=99)/Raw(b'hello'), object()):
            self.assertEqual(parse_packet(raw).protocol, 'OTHER')

    def test_icmp_embedded_tcp_is_not_tcp(self):
        self.assertEqual(parse_packet(IP()/ICMP(type=3)/IP()/TCP()).protocol, 'ICMP')

    def test_flags(self):
        self.assertEqual(parse_packet(IP()/TCP(flags='FSPR AU'.replace(' ', ''))).tcp_flags,
                         ('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'))
