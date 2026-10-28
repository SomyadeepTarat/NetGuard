import unittest
from datetime import datetime, timezone
from backend.models.packet import PacketInfo
from backend.analyzer.flow_engine import FlowEngine


class FlowEngineTests(unittest.TestCase):
    def test_bidirectional_flow_aggregation(self):
        engine = FlowEngine()
        t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 0, 2, tzinfo=timezone.utc)

        # 1. Client SYN -> Server
        p1 = PacketInfo(t0, "192.168.1.10", "10.0.0.1", 54321, 80, "TCP", 64, ("SYN",))
        # 2. Server SYN+ACK -> Client
        p2 = PacketInfo(t1, "10.0.0.1", "192.168.1.10", 80, 54321, "TCP", 64, ("SYN", "ACK"))
        # 3. Client ACK -> Server
        p3 = PacketInfo(t2, "192.168.1.10", "10.0.0.1", 54321, 80, "TCP", 54, ("ACK",))

        flow1 = engine.process_packet(p1)
        flow2 = engine.process_packet(p2)
        flow3 = engine.process_packet(p3)

        self.assertIsNotNone(flow1)
        self.assertEqual(flow1.flow_id, flow2.flow_id)
        self.assertEqual(flow2.flow_id, flow3.flow_id)

        self.assertEqual(flow3.client_ip, "192.168.1.10")
        self.assertEqual(flow3.server_ip, "10.0.0.1")
        self.assertEqual(flow3.packet_count, 3)
        self.assertEqual(flow3.byte_count, 182)
        self.assertEqual(flow3.forward_packets, 2)
        self.assertEqual(flow3.reverse_packets, 1)
        self.assertTrue(flow3.syn_observed)
        self.assertTrue(flow3.syn_ack_observed)
        self.assertTrue(flow3.ack_observed)
        self.assertTrue(flow3.handshake_completed)
        self.assertEqual(flow3.duration, 2.0)

    def test_bounded_flows_and_eviction(self):
        engine = FlowEngine(max_flows=2)
        t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        # Flow 1
        engine.process_packet(PacketInfo(t, "10.0.0.1", "10.0.0.2", 1000, 80, "TCP", 60))
        # Flow 2
        engine.process_packet(PacketInfo(t, "10.0.0.3", "10.0.0.4", 1001, 80, "TCP", 60))
        # Flow 3 - should evict Flow 1
        engine.process_packet(PacketInfo(t, "10.0.0.5", "10.0.0.6", 1002, 80, "TCP", 60))

        flows, total = engine.get_flows()
        self.assertEqual(total, 2)
        self.assertEqual(engine.get_metrics(t.timestamp())["flow_evictions"], 1)

    def test_host_graph_generation(self):
        engine = FlowEngine()
        t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        p = PacketInfo(t, "192.168.1.50", "8.8.8.8", 40000, 53, "UDP", 80, dns_query="dns.google")
        engine.process_packet(p)

        graph = engine.get_host_graph()
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        self.assertIn("Observed communication graph only", graph["disclaimer"])
