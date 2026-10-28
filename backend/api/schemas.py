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


class RobustnessSweepRequest(BaseModel):
    pcap_path: str
    loss_modes: Optional[List[str]] = Field(default_factory=lambda: ["random", "burst", "directional"])
    drop_rates: Optional[List[float]] = Field(default_factory=lambda: [0.05, 0.10, 0.20, 0.30, 0.50])
    seeds: Optional[List[int]] = Field(default_factory=lambda: [11, 23, 37, 51, 79])
    burst_configs: Optional[List[List[int]]] = None
    drop_ips: Optional[List[str]] = None
    max_runs: int = Field(default=50, ge=1, le=100)


class RobustnessRunResponse(BaseModel):
    run_id: str
    pcap_name: str
    pcap_sha256: str
    pcap_size_bytes: int
    status: str
    created_at: float
    completed_at: Optional[float] = None
    total_scenarios: int
    completed_scenarios: int
    current_scenario_id: Optional[str] = None
    stability_verdict: str
    baseline_summary: Dict[str, Any] = Field(default_factory=dict)
    scenario_results: List[Dict[str, Any]] = Field(default_factory=list)
    atlas_matrix: Dict[str, Any] = Field(default_factory=dict)
    envelope: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    disclaimer: str


class ObservationPlanResponse(BaseModel):
    plan_id: str
    target_alert_id: Optional[str] = None
    target_sweep_id: Optional[str] = None
    plan_mode: str = "INCIDENT_LINKED"
    status: str
    insufficient_reason: Optional[str] = None
    total_recommendations: int
    recommendations: List[Dict[str, Any]]
    evidence_summary: Dict[str, Any]
    active_network_action: bool = False
    disclaimer: str


class AnalyzePcapRequest(BaseModel):
    pcap_path: str


class AnalyzePcapResponse(BaseModel):
    status: str
    pcap_path: str
    pcap_sha256: str
    total_windows_evaluated: int
    incidents_recorded: int
    alerts: List[Dict[str, Any]]
    message: str


class LineageVerifyResponse(BaseModel):
    status: str
    is_valid: bool
    events_count: int
    head_hash: Optional[str] = None
    failing_sequence_id: Optional[int] = None
    failing_event_id: Optional[str] = None
    error_reason: Optional[str] = None
    message: Optional[str] = None


class LineageEventItem(BaseModel):
    sequence_id: int
    event_id: str
    event_type: str
    parent_id: Optional[str] = None
    timestamp: float
    iso_time: str
    manifest_digest: str
    previous_hash: str
    event_hash: str
    manifest: Dict[str, Any] = Field(default_factory=dict)


class EvidenceBundleResponse(BaseModel):
    bundle_version: str
    generated_at: float
    target_identifier: str
    target_event: Optional[Dict[str, Any]] = None
    lineage_verification: Dict[str, Any]
    reproducibility_contract: Dict[str, Any]
    security_disclaimer: str

