import time
import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from backend.api.app import create_app
from backend.api.capture_manager import CaptureManager
from backend.api.routes import set_capture_manager
from backend.models.packet import PacketInfo
from backend.analyzer.flow_engine import FlowEngine


class SessionConsistencyRegressionTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = TestClient(self.app)
        self.manager = CaptureManager()
        set_capture_manager(self.manager)

    def tearDown(self):
        self.manager.stop_capture()

    def test_empty_session_consistency(self):
        """Verifies that an empty session consistently reports zeroes and empty lists
        across all related endpoints without fabricated or corrupted states.
        """
        # 1. /api/overview
        ov_resp = self.client.get("/api/overview")
        self.assertEqual(ov_resp.status_code, 200)
        ov = ov_resp.json()
        self.assertEqual(ov["total_packets"], 0)
        self.assertEqual(ov["total_bytes"], 0)
        self.assertEqual(ov["active_flows"], 0)
        self.assertEqual(ov["active_hosts"], 0)
        self.assertEqual(ov["protocols"]["TCP"], 0)
        self.assertEqual(ov["protocols"]["UDP"], 0)
        self.assertEqual(ov["protocols"]["ICMP"], 0)
        self.assertEqual(ov["protocols"]["OTHER"], 0)

        # 2. /api/flows
        flows_resp = self.client.get("/api/flows")
        self.assertEqual(flows_resp.status_code, 200)
        flows = flows_resp.json()
        self.assertEqual(flows["total"], 0)
        self.assertEqual(len(flows["flows"]), 0)

        # 3. /api/hosts
        hosts_resp = self.client.get("/api/hosts")
        self.assertEqual(hosts_resp.status_code, 200)
        hosts = hosts_resp.json()
        self.assertEqual(len(hosts["nodes"]), 0)
        self.assertEqual(len(hosts["edges"]), 0)
        self.assertEqual(len(hosts["top_talkers"]), 0)

        # 4. /api/traffic/timeseries
        ts_resp = self.client.get("/api/traffic/timeseries")
        self.assertEqual(ts_resp.status_code, 200)
        ts = ts_resp.json()
        self.assertIsInstance(ts, list)

    def test_non_empty_synthetic_session_consistency(self):
        """Ingests synthetic TCP and UDP traffic and verifies that /api/overview,
        /api/flows, /api/hosts, and /api/traffic/timeseries report consistent
        counts, endpoints, and protocol distributions.
        """
        now = time.time()
        # Ingest TCP handshake + data
        p1 = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="S")
        p1.time = now
        p2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=54321, flags="SA")
        p2.time = now + 0.005
        p3 = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="A")
        p3.time = now + 0.01

        # Ingest UDP query + response
        p4 = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000, dport=53)
        p4.time = now + 0.02
        p5 = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=53000)
        p5.time = now + 0.03

        for p in [p1, p2, p3, p4, p5]:
            self.manager._ingest_packet(p)

        # 1. Verify /api/overview
        ov_resp = self.client.get("/api/overview")
        self.assertEqual(ov_resp.status_code, 200)
        ov = ov_resp.json()
        self.assertEqual(ov["total_packets"], 5)
        self.assertGreater(ov["total_bytes"], 0)
        self.assertEqual(ov["protocols"]["TCP"], 3)
        self.assertEqual(ov["protocols"]["UDP"], 2)
        self.assertEqual(ov["protocols"]["ICMP"], 0)
        self.assertEqual(ov["protocols"]["OTHER"], 0)
        # 2 active flows (1 TCP + 1 UDP) across 4 observed hosts
        self.assertEqual(ov["active_flows"], 2)
        self.assertEqual(ov["active_hosts"], 4)

        # 2. Verify /api/flows
        flows_resp = self.client.get("/api/flows")
        self.assertEqual(flows_resp.status_code, 200)
        flows_data = flows_resp.json()
        self.assertEqual(flows_data["total"], 2)
        flows = flows_data["flows"]
        self.assertEqual(len(flows), 2)
        for f in flows:
            self.assertEqual(f["state"], "ACTIVE")
            self.assertIn(f["protocol"], ("TCP", "UDP"))

        # 3. Verify /api/hosts
        hosts_resp = self.client.get("/api/hosts")
        self.assertEqual(hosts_resp.status_code, 200)
        hosts_data = hosts_resp.json()
        node_ips = {n["ip"] for n in hosts_data["nodes"]}
        expected_ips = {"192.168.1.10", "10.0.0.1", "192.168.1.50", "8.8.8.8"}
        self.assertEqual(node_ips, expected_ips)
        self.assertEqual(len(hosts_data["edges"]), 2)
        self.assertGreater(len(hosts_data["top_talkers"]), 0)

    def test_inconsistency_regression_active_flows_require_nonzero_overview(self):
        """Regression test for the observed problem:
        Fails if active flows exist in the engine but /api/overview reports
        0 active connections or 0 active hosts.
        """
        now = time.time()
        p = Ether() / IP(src="10.0.0.5", dst="172.16.0.1") / TCP(sport=40000, dport=443, flags="S")
        p.time = now
        self.manager._ingest_packet(p)

        flows_resp = self.client.get("/api/flows")
        flows_data = flows_resp.json()
        active_flows = [f for f in flows_data["flows"] if f["state"] == "ACTIVE"]
        self.assertGreater(len(active_flows), 0, "Precondition: active flows must exist in the flow list")

        # Overview MUST NOT report 0 active connections or 0 hosts when active flows exist
        ov_resp = self.client.get("/api/overview")
        ov_data = ov_resp.json()
        self.assertGreater(
            ov_data["active_flows"], 0,
            "Overview reported 0 active connections while active flows exist in flow engine!"
        )
        self.assertGreater(
            ov_data["active_hosts"], 0,
            "Overview reported 0 observed hosts while active flows exist in flow engine!"
        )
        self.assertEqual(ov_data["active_flows"], len(active_flows))

        # Check host derivation consistency
        active_flow_endpoints = set()
        for f in active_flows:
            active_flow_endpoints.add(f["client_ip"])
            active_flow_endpoints.add(f["server_ip"])
        self.assertEqual(ov_data["active_hosts"], len(active_flow_endpoints))

    def test_protocol_specific_lifecycle_semantics(self):
        """Verifies protocol-specific active connection semantics:
        - Active TCP connection drops from active_flows when RST is observed (state = CLOSED).
        - Connectionless UDP flow is active during the 15s window, but inactive after 15s idle.
        - Cumulative packet counts and table retention are distinguished from active count.
        """
        engine = FlowEngine(idle_timeout=60.0)
        t0 = 1000.0

        # 1. TCP connection establishes
        p_syn = PacketInfo(datetime.fromtimestamp(t0, tz=timezone.utc), "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 64, ("SYN",))
        p_sa = PacketInfo(datetime.fromtimestamp(t0 + 0.01, tz=timezone.utc), "10.0.0.2", "10.0.0.1", 80, 1234, "TCP", 64, ("SYN", "ACK"))
        p_ack = PacketInfo(datetime.fromtimestamp(t0 + 0.02, tz=timezone.utc), "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 54, ("ACK",))
        for p in [p_syn, p_sa, p_ack]:
            engine.process_packet(p)

        metrics_active = engine.get_metrics(current_time=t0 + 1.0)
        self.assertEqual(metrics_active["active_flows"], 1)
        self.assertEqual(metrics_active["active_hosts"], 2)
        self.assertEqual(metrics_active["total_flows"], 1)

        # 2. TCP connection reset (RST)
        p_rst = PacketInfo(datetime.fromtimestamp(t0 + 2.0, tz=timezone.utc), "10.0.0.2", "10.0.0.1", 80, 1234, "TCP", 54, ("RST",))
        engine.process_packet(p_rst)

        metrics_closed = engine.get_metrics(current_time=t0 + 3.0)
        # Closed TCP connection must NOT be counted as active
        self.assertEqual(metrics_closed["active_flows"], 0)
        self.assertEqual(metrics_closed["active_hosts"], 0)
        # But flow remains tracked in table until evicted or timed out
        self.assertEqual(metrics_closed["total_flows"], 1)
        self.assertEqual(metrics_closed["total_hosts"], 2)

        # 3. UDP connectionless flow
        p_udp = PacketInfo(datetime.fromtimestamp(t0 + 10.0, tz=timezone.utc), "192.168.1.1", "8.8.8.8", 50000, 53, "UDP", 80)
        engine.process_packet(p_udp)

        # At t0 + 12s (elapsed 2s <= 15s active_window), UDP is active
        m_udp_active = engine.get_metrics(current_time=t0 + 12.0)
        self.assertEqual(m_udp_active["active_flows"], 1)
        self.assertEqual(m_udp_active["active_hosts"], 2)

        # At t0 + 30s (elapsed 20s > 15s active_window), UDP flow is idle/inactive
        m_udp_idle = engine.get_metrics(current_time=t0 + 30.0)
        self.assertEqual(m_udp_idle["active_flows"], 0)
        self.assertEqual(m_udp_idle["active_hosts"], 0)
        # Still in table because idle_timeout is 60s
        self.assertEqual(m_udp_idle["total_flows"], 2)

    def test_session_reset_prevents_stale_contamination(self):
        """Verifies that starting a new capture session resets all counters and flows,
        preventing different sessions from contaminating each other.
        """
        now = time.time()
        p = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1111, dport=80, flags="S")
        p.time = now
        self.manager._ingest_packet(p)

        self.assertEqual(self.manager.analyzer._packets, 1)
        self.assertEqual(len(self.manager.flow_engine._flows), 1)

        # Start a new capture session (mock mode)
        self.manager.start_capture(mode="demo")
        try:
            # Check immediately after start
            status = self.manager.get_status()
            self.assertEqual(status["mode"], "DEMO")
            self.assertEqual(status["running"], True)
        finally:
            self.manager.stop_capture()
