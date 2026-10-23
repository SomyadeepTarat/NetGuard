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
