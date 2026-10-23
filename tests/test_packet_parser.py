import unittest
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR
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
        self.assertEqual(result.ip_version, 4)

    def test_udp(self):
        result = parse_packet(IP()/UDP(sport=53000, dport=53))
        self.assertEqual((result.protocol, result.source_port, result.destination_port), ('UDP', 53000, 53))
        self.assertEqual(result.tcp_flags, ())
        self.assertEqual(result.ip_version, 4)

    def test_icmp(self):
        result = parse_packet(IP()/ICMP())
        self.assertEqual(result.protocol, 'ICMP')
        self.assertIsNone(result.source_port)
        self.assertIsNone(result.destination_port)
        self.assertEqual(result.ip_version, 4)

    def test_arp_metadata(self):
        raw = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/ARP(
            op=1, hwsrc='00:00:00:00:00:01', psrc='192.168.1.100',
            hwdst='00:00:00:00:00:02', pdst='192.168.1.1'
        )
        result = parse_packet(raw)
        self.assertEqual(result.protocol, 'ARP')
        self.assertEqual(result.source_ip, '192.168.1.100')
        self.assertEqual(result.destination_ip, '192.168.1.1')
        self.assertEqual(result.arp_opcode, 'who-has')
        self.assertEqual(result.arp_hwsrc, '00:00:00:00:00:01')
        self.assertIsNone(result.source_port)

    def test_ipv6_and_icmpv6(self):
        tcp_v6 = IPv6(src='2001:db8::1', dst='2001:db8::2')/TCP(sport=9000, dport=443, flags='S')
        result_tcp = parse_packet(tcp_v6)
        self.assertEqual(result_tcp.protocol, 'TCP')
        self.assertEqual(result_tcp.ip_version, 6)
        self.assertEqual(result_tcp.source_ip, '2001:db8::1')
        self.assertEqual(result_tcp.destination_ip, '2001:db8::2')

        icmp_v6 = IPv6(src='2001:db8::1', dst='2001:db8::2')/ICMPv6EchoRequest()
        result_icmp = parse_packet(icmp_v6)
        self.assertEqual(result_icmp.protocol, 'ICMPv6')
        self.assertEqual(result_icmp.ip_version, 6)

    def test_dns_metadata_parsing(self):
        query_pkt = IP()/UDP(sport=49152, dport=53)/DNS(rd=1, qd=DNSQR(qname='api.threat-observatory.internal', qtype='A'))
        result = parse_packet(query_pkt)
        self.assertEqual(result.protocol, 'UDP')
        self.assertEqual(result.dns_query, 'api.threat-observatory.internal')
        self.assertEqual(result.dns_qtype, 'A')
        self.assertFalse(result.dns_is_response)

    def test_unsupported_and_malformed(self):
        for raw in (IP(proto=99)/Raw(b'hello'), object()):
            self.assertEqual(parse_packet(raw).protocol, 'OTHER')

    def test_icmp_embedded_tcp_is_not_tcp(self):
        self.assertEqual(parse_packet(IP()/ICMP(type=3)/IP()/TCP()).protocol, 'ICMP')

    def test_flags(self):
        self.assertEqual(parse_packet(IP()/TCP(flags='FSPR AU'.replace(' ', ''))).tcp_flags,
                         ('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'))
