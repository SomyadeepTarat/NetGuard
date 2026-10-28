"""Capture Quality and Observation Completeness Subsystem.

Provides honest, transparent telemetry on capture observability.
Distinguishes kernel/driver packet drops, internal bounded queue drops,
flow evictions, and hypothetical simulation loss into separate, non-conflated dimensions.
"""
from dataclasses import dataclass, field
import platform
import time
from typing import Any, Dict, List, Optional


@dataclass
class QualityIndicator:
    name: str
    value: Any
    status: str  # HEALTHY, DEGRADED, UNKNOWN, UNAVAILABLE
    availability: str  # AVAILABLE, UNAVAILABLE, UNKNOWN
    source: str
    description: str
    limitations: str
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "status": self.status,
            "availability": self.availability,
            "source": self.source,
            "description": self.description,
            "limitations": self.limitations,
            "last_updated": self.last_updated,
        }


class CaptureQualityService:
    def __init__(self, mode: str = "DEMO", interface: Optional[str] = None):
        self._mode = mode  # LIVE, PCAP_REPLAY, DEMO
        self._interface = interface or "synthetic-demo"
        self._packets_received = 0
        self._queue_drops = 0
        self._flow_evictions = 0
        self._parser_errors = 0
        self._out_of_order_packets = 0
        self._tcp_flows_total = 0
        self._tcp_flows_bidirectional = 0
        self._kernel_drops: Optional[int] = None
        self._kernel_drop_supported = False
        self._platform_os = platform.system()

    def set_mode(self, mode: str, interface: Optional[str] = None) -> None:
        self._mode = mode
        if interface:
            self._interface = interface

    def record_packet(self, out_of_order: bool = False, parser_error: bool = False) -> None:
        self._packets_received += 1
        if out_of_order:
            self._out_of_order_packets += 1
        if parser_error:
            self._parser_errors += 1

    def record_queue_drop(self, count: int = 1) -> None:
        self._queue_drops += count

    def record_flow_eviction(self, count: int = 1) -> None:
        self._flow_evictions += count

    def record_tcp_flow(self, bidirectional: bool) -> None:
        self._tcp_flows_total += 1
        if bidirectional:
            self._tcp_flows_bidirectional += 1

    def set_kernel_drops(self, drops: Optional[int], supported: bool = True) -> None:
        self._kernel_drops = drops
        self._kernel_drop_supported = supported

    def get_quality_report(self) -> dict:
        now = time.time()
        indicators: List[QualityIndicator] = []

        # 1. Mode and Interface context
        indicators.append(QualityIndicator(
            name="Capture Backend & Mode",
            value=f"{self._mode} ({self._interface})",
            status="HEALTHY",
            availability="AVAILABLE",
            source="NetGuard Orchestrator",
            description="Active ingestion mode and source identifier.",
            limitations="Synthetic/demo data does not represent live network traffic.",
            last_updated=now
        ))

        # 2. Kernel / NIC Drops
        if self._mode in ("PCAP_REPLAY", "DEMO"):
            indicators.append(QualityIndicator(
                name="OS / Kernel Packet Drops",
                value=None,
                status="UNAVAILABLE",
                availability="UNAVAILABLE",
                source="Offline Engine",
                description="NIC and OS socket drop counters.",
                limitations="Offline PCAP and synthetic replays do not possess live NIC ring-buffer counters.",
                last_updated=now
            ))
        elif not self._kernel_drop_supported or self._kernel_drops is None:
            reason = (
                "Npcap/libpcap socket stats not supported or accessible on this Windows host."
                if self._platform_os == "Windows"
                else "Kernel capture handle did not expose driver drop metrics."
            )
            indicators.append(QualityIndicator(
                name="OS / Kernel Packet Drops",
                value=None,
                status="UNAVAILABLE",
                availability="UNAVAILABLE",
                source="OS Capture Driver",
                description="Packets dropped by NIC ring buffer or OS kernel before reaching userspace.",
                limitations=f"Telemetry unavailable: {reason}. Not zero drops.",
                last_updated=now
            ))
        else:
            status = "HEALTHY" if self._kernel_drops == 0 else "DEGRADED"
            indicators.append(QualityIndicator(
                name="OS / Kernel Packet Drops",
                value=self._kernel_drops,
                status=status,
                availability="AVAILABLE",
                source="libpcap/Npcap driver counter",
                description="Cumulative packets dropped by OS/driver during this capture session.",
                limitations="Does not detect loss upstream of the monitoring NIC (e.g. switch span overflow).",
                last_updated=now
            ))

        # 3. Internal Application Queue Drops
        q_status = "HEALTHY" if self._queue_drops == 0 else "DEGRADED"
        indicators.append(QualityIndicator(
            name="Application Queue Drops",
            value=self._queue_drops,
            status=q_status,
            availability="AVAILABLE",
            source="NetGuard Bounded Ingestion Queue",
            description="Packets dropped because analyzer worker was under backpressure.",
            limitations="Represents internal processing exhaustion; does not imply network packet loss.",
            last_updated=now
        ))

        # 4. Flow Table Evictions
        f_status = "HEALTHY" if self._flow_evictions == 0 else "DEGRADED"
        indicators.append(QualityIndicator(
            name="Flow State Evictions",
            value=self._flow_evictions,
            status=f_status,
            availability="AVAILABLE",
            source="NetGuard Flow Engine",
            description="Active flow records evicted prematurely due to table capacity limits.",
            limitations="Evicted flows may lead to incomplete connection duration and missed handshake ACKs.",
            last_updated=now
        ))

        # 5. Out-of-Order Packets
        ooo_status = "HEALTHY" if self._out_of_order_packets == 0 else "DEGRADED"
        indicators.append(QualityIndicator(
            name="Out-of-Order / Late Packets",
            value=self._out_of_order_packets,
            status=ooo_status,
            availability="AVAILABLE",
            source="NetGuard Feature Extractor",
            description="Packets received with timestamps older than the advancing feature watermark.",
            limitations="Late packets are excluded from feature calculation to avoid back-dated model bias.",
            last_updated=now
        ))

        # 6. Parser Errors & Unsupported Frames
        p_status = "HEALTHY" if self._parser_errors == 0 else "DEGRADED"
        indicators.append(QualityIndicator(
            name="Malformed / Parser Errors",
            value=self._parser_errors,
            status=p_status,
            availability="AVAILABLE",
            source="NetGuard Packet Parser",
            description="Frames that could not be parsed into valid metadata.",
            limitations="Malformed frames are accounted for in totals but excluded from protocol-specific metrics.",
            last_updated=now
        ))

        # 7. Bidirectional Handshake Observability
        ratio = (
            round(self._tcp_flows_bidirectional / self._tcp_flows_total, 4)
            if self._tcp_flows_total > 0
            else None
        )
        h_status = "HEALTHY" if ratio is None or ratio >= 0.5 else "DEGRADED"
        indicators.append(QualityIndicator(
            name="Bidirectional Handshake Observability",
            value=f"{ratio * 100:.1f}%" if ratio is not None else "No TCP flows yet",
            status=h_status,
            availability="AVAILABLE" if ratio is not None else "UNKNOWN",
            source="NetGuard Flow Engine",
            description="Proportion of observed TCP flows with both forward and reverse packets.",
            limitations="Asymmetric routing or sensor placement can prevent observation of reverse replies.",
            last_updated=now
        ))

        # Overall Status Computation
        if any(ind.status == "DEGRADED" for ind in indicators):
            overall_status = "DEGRADED"
            overall_summary = "Observation quality is degraded due to queue drops, flow evictions, or out-of-order packets. Threat alerts should be reviewed with caution."
        elif all(ind.status in ("HEALTHY", "UNAVAILABLE") for ind in indicators):
            overall_status = "HEALTHY"
            overall_summary = "Capture pipeline telemetry is healthy with no internal drops or evictions detected."
        else:
            overall_status = "UNKNOWN"
            overall_summary = "Observation quality status is partially uninitialized."

        return {
            "overall_status": overall_status,
            "overall_summary": overall_summary,
            "mode": self._mode,
            "interface": self._interface,
            "packets_received": self._packets_received,
            "indicators": [ind.to_dict() for ind in indicators],
            "timestamp": now,
        }
