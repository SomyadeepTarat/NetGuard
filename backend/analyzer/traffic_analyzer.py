from collections import deque
from threading import Lock
from time import monotonic, time
from typing import Optional
from backend.models.packet import PacketInfo
from backend.analyzer.flow_engine import FlowEngine


class TrafficAnalyzer:
    """Thread-safe sliding-window and cumulative packet telemetry analyzer."""

    def __init__(self, recent_limit: int = 15, clock=monotonic, flow_engine: Optional[FlowEngine] = None):
        self._clock = clock
        self._started = clock()
        self._lock = Lock()
        self._recent = deque(maxlen=recent_limit)
        self._packets = self._bytes = 0
        # Standard base protocol distribution contract
        self._protocols = dict.fromkeys(("TCP", "UDP", "ICMP", "OTHER"), 0)
        # Extended protocol telemetry (IPv6, ARP, DNS metadata, parser errors)
        self._extended_protocols = {"IPv6": 0, "ICMPv6": 0, "ARP": 0, "DNS": 0, "PARSER_ERRORS": 0}
        self._flow_engine = flow_engine or FlowEngine()

    @property
    def flow_engine(self) -> FlowEngine:
        return self._flow_engine

    def process(self, packet: PacketInfo):
        with self._lock:
            self._packets += 1
            self._bytes += packet.packet_size
            proto_key = packet.protocol if packet.protocol in self._protocols else "OTHER"
            self._protocols[proto_key] += 1

            if packet.protocol == "ARP":
                self._extended_protocols["ARP"] += 1
            if packet.protocol == "ICMPv6":
                self._extended_protocols["ICMPv6"] += 1
            if packet.ip_version == 6:
                self._extended_protocols["IPv6"] += 1
            if packet.dns_query is not None:
                self._extended_protocols["DNS"] += 1
            if packet.parser_error is not None:
                self._extended_protocols["PARSER_ERRORS"] += 1

            self._recent.append(packet)

        # Update flow engine
        if self._flow_engine is not None:
            self._flow_engine.process_packet(packet)

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = max(0.0, self._clock() - self._started)
            base = {
                "total_packets": self._packets,
                "total_bytes": self._bytes,
                "protocols": self._protocols.copy(),
                "extended_protocols": self._extended_protocols.copy(),
                "elapsed": elapsed,
                "packets_per_second": self._packets / elapsed if elapsed else 0.0,
                "bytes_per_second": self._bytes / elapsed if elapsed else 0.0,
                "recent": tuple(self._recent),
            }

        if self._flow_engine:
            base["flow_metrics"] = self._flow_engine.get_metrics()
        return base
