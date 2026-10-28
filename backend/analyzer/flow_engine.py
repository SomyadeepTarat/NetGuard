"""Bounded bidirectional flow aggregation, rolling metrics, and observed host communication graph.

Explicit limitation: The host graph represents observed packet communication
relationships only, not physical topology, switching fabrics, or unobserved routers.
"""
from collections import deque, OrderedDict
from dataclasses import dataclass, field
import hashlib
from threading import Lock
import time
from typing import Dict, List, Optional, Set, Tuple
from backend.models.packet import PacketInfo


@dataclass
class FlowRecord:
    flow_id: str
    client_ip: str
    client_port: Optional[int]
    server_ip: str
    server_port: Optional[int]
    protocol: str
    first_seen: float
    last_seen: float
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    forward_bytes: int = 0
    reverse_packets: int = 0
    reverse_bytes: int = 0
    tcp_flags_forward: Set[str] = field(default_factory=set)
    tcp_flags_reverse: Set[str] = field(default_factory=set)
    syn_observed: bool = False
    syn_ack_observed: bool = False
    ack_observed: bool = False
    handshake_completed: bool = False
    reset_observed: bool = False
    fin_observed: bool = False
    dns_queries: List[str] = field(default_factory=list)
    state: str = "ACTIVE"  # ACTIVE, CLOSED, TIMED_OUT

    def is_active(self, current_time: float, active_window: float = 15.0) -> bool:
        """Determines whether this flow is actively communicating at current_time.
        
        Protocol-specific semantics:
        - TCP: A connection terminated by RST or FIN teardown is marked CLOSED and
          is not active. An unclosed TCP flow is active if packets were exchanged
          within active_window.
        - UDP / ICMP / OTHER: Stateless transports have no explicit teardown flags;
          they are defined as active strictly if packets were exchanged within active_window.
        """
        if self.state == "CLOSED":
            return False
        elapsed = current_time - self.last_seen
        # Allow slight microsecond float/scheduling skew: -1.0s to active_window
        return -1.0 <= elapsed <= active_window

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "protocol": self.protocol,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 4),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packets": self.forward_packets,
            "forward_bytes": self.forward_bytes,
            "reverse_packets": self.reverse_packets,
            "reverse_bytes": self.reverse_bytes,
            "tcp_flags_forward": sorted(self.tcp_flags_forward),
            "tcp_flags_reverse": sorted(self.tcp_flags_reverse),
            "handshake": {
                "syn_observed": self.syn_observed,
                "syn_ack_observed": self.syn_ack_observed,
                "ack_observed": self.ack_observed,
                "completed": self.handshake_completed,
                "reset_observed": self.reset_observed,
                "fin_observed": self.fin_observed,
            },
            "dns_queries": list(self.dns_queries[:5]),
            "state": self.state,
        }


class FlowEngine:
    def __init__(self, max_flows: int = 10000, idle_timeout: float = 60.0):
        self._max_flows = max_flows
        self._idle_timeout = idle_timeout
        self._lock = Lock()
        # Maps 5-tuple (src, sport, dst, dport, proto) and reverse to canonical flow_id
        self._lookup: OrderedDict[Tuple[Optional[str], Optional[int], Optional[str], Optional[int], str], str] = OrderedDict()
        self._flows: Dict[str, FlowRecord] = {}
        self._recent_events: deque = deque(maxlen=20000)  # (timestamp, size, is_new_flow)
        self._flow_evictions = 0
        self._total_flows_created = 0
        self._latest_packet_time: Optional[float] = None

    def reset(self) -> None:
        """Resets engine state to an empty session."""
        with self._lock:
            self._lookup.clear()
            self._flows.clear()
            self._recent_events.clear()
            self._flow_evictions = 0
            self._total_flows_created = 0
            self._latest_packet_time = None

    def _canonical_id(self, p: PacketInfo) -> str:
        s_ip, d_ip = p.source_ip or "-", p.destination_ip or "-"
        s_port, d_port = p.source_port or 0, p.destination_port or 0
        # Ordered for stable hash
        pair = sorted([(s_ip, s_port), (d_ip, d_port)])
        raw = f"{pair[0][0]}:{pair[0][1]}-{pair[1][0]}:{pair[1][1]}-{p.protocol}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def process_packet(self, packet: PacketInfo) -> Optional[FlowRecord]:
        t = packet.timestamp.timestamp()
        s_ip = packet.source_ip
        d_ip = packet.destination_ip
        if not s_ip or not d_ip:
            return None

        tuple_fwd = (s_ip, packet.source_port, d_ip, packet.destination_port, packet.protocol)
        tuple_rev = (d_ip, packet.destination_port, s_ip, packet.source_port, packet.protocol)

        with self._lock:
            if self._latest_packet_time is None or t > self._latest_packet_time:
                self._latest_packet_time = t

            # 1. Check expiration of old lookup tuples
            self._prune_expired_locked(t)

            is_forward = True
            flow_id = None
            is_new_flow = False

            if tuple_fwd in self._lookup:
                flow_id = self._lookup[tuple_fwd]
                is_forward = True
                self._lookup.move_to_end(tuple_fwd)
            elif tuple_rev in self._lookup:
                flow_id = self._lookup[tuple_rev]
                is_forward = False
                self._lookup.move_to_end(tuple_rev)
            else:
                # New flow
                is_new_flow = True
                self._total_flows_created += 1
                flow_id = f"{packet.protocol.lower()}-{self._canonical_id(packet)}"

                # Check bounds
                if len(self._flows) >= self._max_flows:
                    # Evict oldest inactive flow
                    oldest_id, oldest_flow = min(self._flows.items(), key=lambda item: item[1].last_seen)
                    self._remove_flow_locked(oldest_id)
                    self._flow_evictions += 1

                record = FlowRecord(
                    flow_id=flow_id,
                    client_ip=s_ip,
                    client_port=packet.source_port,
                    server_ip=d_ip,
                    server_port=packet.destination_port,
                    protocol=packet.protocol,
                    first_seen=t,
                    last_seen=t,
                )
                self._flows[flow_id] = record
                self._lookup[tuple_fwd] = flow_id
                self._lookup[tuple_rev] = flow_id

            flow = self._flows[flow_id]
            is_forward = (s_ip == flow.client_ip and packet.source_port == flow.client_port)

            flow.last_seen = t
            flow.duration = max(0.0, t - flow.first_seen)
            flow.packet_count += 1
            flow.byte_count += packet.packet_size

            if is_forward:
                flow.forward_packets += 1
                flow.forward_bytes += packet.packet_size
                flow.tcp_flags_forward.update(packet.tcp_flags)
            else:
                flow.reverse_packets += 1
                flow.reverse_bytes += packet.packet_size
                flow.tcp_flags_reverse.update(packet.tcp_flags)

            # Handshake tracking for TCP
            if packet.protocol == "TCP":
                flags = set(packet.tcp_flags)
                if is_forward and "SYN" in flags and "ACK" not in flags:
                    flow.syn_observed = True
                elif not is_forward and {"SYN", "ACK"} <= flags:
                    flow.syn_ack_observed = True
                elif is_forward and "ACK" in flags and "SYN" not in flags:
                    if flow.syn_observed and flow.syn_ack_observed:
                        flow.handshake_completed = True
                    flow.ack_observed = True
                
                if "RST" in flags:
                    flow.reset_observed = True
                    flow.state = "CLOSED"
                elif "FIN" in flags:
                    flow.fin_observed = True
                    if "ACK" in flags:
                        flow.state = "CLOSED"

            # DNS Query recording
            if packet.dns_query and packet.dns_query not in flow.dns_queries:
                flow.dns_queries.append(packet.dns_query)

            self._recent_events.append((t, packet.packet_size, is_new_flow))
            return flow

    def _prune_expired_locked(self, current_time: float) -> None:
        threshold = current_time - self._idle_timeout
        to_remove = []
        for fid, f in self._flows.items():
            if f.last_seen < threshold:
                f.state = "TIMED_OUT"
                to_remove.append(fid)
        for fid in to_remove:
            self._remove_flow_locked(fid)

    def _remove_flow_locked(self, flow_id: str) -> None:
        if flow_id in self._flows:
            f = self._flows.pop(flow_id)
            tuple_fwd = (f.client_ip, f.client_port, f.server_ip, f.server_port, f.protocol)
            tuple_rev = (f.server_ip, f.server_port, f.client_ip, f.client_port, f.protocol)
            self._lookup.pop(tuple_fwd, None)
            self._lookup.pop(tuple_rev, None)

    def get_flows(self, limit: int = 50, offset: int = 0, protocol: Optional[str] = None, search: Optional[str] = None) -> Tuple[List[dict], int]:
        with self._lock:
            matched = list(self._flows.values())
            if protocol:
                matched = [f for f in matched if f.protocol.upper() == protocol.upper()]
            if search:
                s = search.lower()
                matched = [f for f in matched if s in f.client_ip.lower() or s in f.server_ip.lower() or s in str(f.client_port) or s in str(f.server_port) or any(s in q.lower() for q in f.dns_queries)]
            
            # Sort by last_seen descending
            matched.sort(key=lambda f: f.last_seen, reverse=True)
            total = len(matched)
            sliced = matched[offset:offset + limit]
            return [f.to_dict() for f in sliced], total

    def get_flow_by_id(self, flow_id: str) -> Optional[dict]:
        with self._lock:
            flow = self._flows.get(flow_id)
            return flow.to_dict() if flow else None

    def get_metrics(self, current_time: Optional[float] = None) -> dict:
        with self._lock:
            if current_time is not None:
                now = current_time
            elif self._latest_packet_time is not None and abs(time.time() - self._latest_packet_time) > 3600:
                # If packets use an offline historical timestamp domain (e.g. test fixtures),
                # anchor evaluation to the latest packet timestamp seen by the engine.
                now = self._latest_packet_time
            else:
                now = time.time()

            # Calculate rates over 1s, 5s, 30s
            r1_pkts = r1_bytes = 0
            r5_pkts = r5_bytes = r5_new_flows = 0
            r30_pkts = r30_bytes = 0

            for t, sz, is_new in reversed(self._recent_events):
                age = now - t
                if age < 0:
                    age = 0.0
                if age <= 1.0:
                    r1_pkts += 1
                    r1_bytes += sz
                if age <= 5.0:
                    r5_pkts += 1
                    r5_bytes += sz
                    if is_new:
                        r5_new_flows += 1
                if age <= 30.0:
                    r30_pkts += 1
                    r30_bytes += sz
                else:
                    break

            # Active hosts & flows based on protocol-appropriate semantics
            active_flows = [f for f in self._flows.values() if f.is_active(now, active_window=15.0)]
            active_hosts = set()
            for f in active_flows:
                active_hosts.add(f.client_ip)
                active_hosts.add(f.server_ip)

            total_hosts = set()
            for f in self._flows.values():
                total_hosts.add(f.client_ip)
                total_hosts.add(f.server_ip)

            # Top talkers (bytes)
            host_bytes: Dict[str, int] = {}
            for f in self._flows.values():
                host_bytes[f.client_ip] = host_bytes.get(f.client_ip, 0) + f.forward_bytes
                host_bytes[f.server_ip] = host_bytes.get(f.server_ip, 0) + f.reverse_bytes

            top_talkers = sorted(
                [{"ip": ip, "bytes": b} for ip, b in host_bytes.items()],
                key=lambda x: x["bytes"],
                reverse=True
            )[:5]

            return {
                "active_flows": len(active_flows),
                "total_flows": len(self._flows),
                "active_hosts": len(active_hosts),
                "total_hosts": len(total_hosts),
                "flow_evictions": self._flow_evictions,
                "rates": {
                    "1s": {"packets_per_sec": r1_pkts, "bytes_per_sec": r1_bytes},
                    "5s": {"packets_per_sec": round(r5_pkts / 5.0, 2), "bytes_per_sec": round(r5_bytes / 5.0, 2), "new_flows_per_sec": round(r5_new_flows / 5.0, 2)},
                    "30s": {"packets_per_sec": round(r30_pkts / 30.0, 2), "bytes_per_sec": round(r30_bytes / 30.0, 2)},
                },
                "top_talkers": top_talkers,
            }

    def get_host_graph(self) -> dict:
        """Returns the observed communication graph.
        
        Explicit limitation: Depicts observed packet exchanges only, not physical topology.
        """
        with self._lock:
            nodes: Dict[str, dict] = {}
            edges: Dict[Tuple[str, str], dict] = {}

            for f in self._flows.values():
                # Client node
                if f.client_ip not in nodes:
                    nodes[f.client_ip] = {
                        "id": f.client_ip,
                        "ip": f.client_ip,
                        "sent_bytes": 0,
                        "recv_bytes": 0,
                        "flows": 0,
                        "role": "client"
                    }
                # Server node
                if f.server_ip not in nodes:
                    nodes[f.server_ip] = {
                        "id": f.server_ip,
                        "ip": f.server_ip,
                        "sent_bytes": 0,
                        "recv_bytes": 0,
                        "flows": 0,
                        "role": "server"
                    }

                nodes[f.client_ip]["sent_bytes"] += f.forward_bytes
                nodes[f.client_ip]["recv_bytes"] += f.reverse_bytes
                nodes[f.client_ip]["flows"] += 1

                nodes[f.server_ip]["sent_bytes"] += f.reverse_bytes
                nodes[f.server_ip]["recv_bytes"] += f.forward_bytes
                nodes[f.server_ip]["flows"] += 1

                edge_key = (f.client_ip, f.server_ip)
                if edge_key not in edges:
                    edges[edge_key] = {
                        "source": f.client_ip,
                        "target": f.server_ip,
                        "protocol": f.protocol,
                        "bytes": 0,
                        "packets": 0,
                        "flows": 0,
                        "last_seen": f.last_seen,
                    }
                edges[edge_key]["bytes"] += f.byte_count
                edges[edge_key]["packets"] += f.packet_count
                edges[edge_key]["flows"] += 1
                edges[edge_key]["last_seen"] = max(edges[edge_key]["last_seen"], f.last_seen)

            return {
                "nodes": list(nodes.values())[:100],  # bounded to top 100 hosts
                "edges": list(edges.values())[:200],  # bounded to top 200 links
                "disclaimer": "Observed communication graph only: Depicts observed communication relationships between IP endpoints; does not infer physical switches, routers, or unobserved topology."
            }
