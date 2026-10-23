"""Pydantic schemas for the typed NetGuard REST API."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    capture_running: bool
    mode: str
    interface: str
    model_loaded: bool
    model_scope: str
    uptime_seconds: float
    total_packets: int
    capture_quality_status: str


class InterfaceItem(BaseModel):
    name: str
    description: str
    ip: Optional[str] = None
    is_default: bool = False


class CaptureStartRequest(BaseModel):
    mode: str = Field(default="demo", pattern="^(demo|live|pcap)$")
    interface: Optional[str] = None
    pcap_path: Optional[str] = None
    capture_filter: Optional[str] = None


class ReplayStartRequest(BaseModel):
    pcap_path: str
    loss_mode: str = Field(default="random", pattern="^(random|burst|directional)$")
    drop_rate: float = Field(default=0.1, ge=0.0, lt=1.0)
    seed: int = Field(default=42, ge=0)
    burst_size: int = Field(default=4, ge=1, le=50)
    burst_interval: int = Field(default=20, ge=2, le=200)
    drop_ip: Optional[str] = None


class OverviewResponse(BaseModel):
    """Authoritative snapshot of session metrics and telemetry.
    
    Metric Semantics:
    - total_packets: Cumulative frames ingested in the current capture session.
    - total_bytes: Cumulative wire bytes ingested in the current capture session.
    - packets_per_second / bytes_per_second: Session-wide cumulative rates.
    - active_flows: Instantaneous count of concurrent flows meeting active criteria:
      * TCP: Not terminated by RST or FIN-ACK teardown, and observed within 15s.
      * UDP/ICMP/OTHER: Packets observed within the 15s sliding activity window.
    - active_hosts: Distinct IP endpoints participating in active_flows.
    - total_flows: Cumulative/retained flows currently tracked in the flow table.
    - total_hosts: Distinct IP endpoints across all tracked flows.
    - rates: Sliding window throughput rates (1s, 5s, 30s).
    """
    status: str
    mode: str
    interface: str
    uptime_seconds: float
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    active_hosts: int
    active_flows: int
    total_flows: Optional[int] = None
    total_hosts: Optional[int] = None
    protocols: Dict[str, int]
    extended_protocols: Dict[str, int]
    rates: Dict[str, Any]
    capture_quality: Dict[str, Any]
    recent_alerts_count: int


class TimeseriesPoint(BaseModel):
    timestamp: float
    iso_time: str
    packets_per_sec: float
    bytes_per_sec: float


class HostGraphNode(BaseModel):
    id: str
    ip: str
    sent_bytes: int
    recv_bytes: int
    flows: int
    role: str


class HostGraphEdge(BaseModel):
    source: str
    target: str
    protocol: str
    bytes: int
    packets: int
    flows: int
    last_seen: float


class HostGraphResponse(BaseModel):
    nodes: List[HostGraphNode]
    edges: List[HostGraphEdge]
    disclaimer: str
    top_talkers: List[Dict[str, Any]]
