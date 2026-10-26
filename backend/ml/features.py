"""Bounded rolling-window features shared by replay, training, and live detection."""
from collections import deque, OrderedDict
import math

FEATURES = ['packets', 'bytes_per_second', 'unique_ports', 'unique_hosts',
            'syn_rate', 'rst_fraction', 'response_fraction', 'mean_size',
            'udp_fraction', 'icmp_fraction', 'mean_gap', 'completed_fraction']
SCHEMA = 'netguard-source-window-v1'


class FeatureExtractor:
    def __init__(self, window=5.0, interval=1.0, max_sources=256, max_events=4096, max_flows=20000):
        if window <= 0 or interval <= 0:
            raise ValueError('Window and interval must be positive')
        self.window, self.interval = window, interval
        self.max_sources, self.max_events, self.max_flows = max_sources, max_events, max_flows
        self.sources = OrderedDict()
        self.flows = OrderedDict()
        self.next_tick = self.last_time = self.watermark = None
        self.evictions = self.late_packets = 0

    def advance(self, timestamp):
        """Emit before ingesting packets at/after the boundary; never use future data."""
        if not math.isfinite(timestamp):
            raise ValueError('Invalid timestamp')
        if self.next_tick is None:
            self.next_tick = timestamp + self.interval
        rows = []
        # Large capture gaps need only one final window, not millions of empty ticks.
        if timestamp - self.next_tick > self.window + self.interval:
            rows.extend(self._snapshot(self.next_tick))
            self.next_tick = timestamp
        while self.next_tick <= timestamp:
            rows.extend(self._snapshot(self.next_tick))
            self.watermark = self.next_tick
            self.next_tick += self.interval
        return rows

    def process(self, packet):
        t = packet.timestamp.timestamp()
        if (self.last_time is not None and t < self.last_time) or (self.watermark is not None and t < self.watermark):
            self.late_packets += 1
            return []
        rows = self.advance(t)
        self.last_time = t
        if not packet.source_ip or packet.protocol not in ('TCP', 'UDP', 'ICMP'):
            return rows
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port, packet.protocol)
        reverse = (key[2], key[3], key[0], key[1], key[4])
        # Expire orientation state; first observed direction is the originator.
        while self.flows and next(iter(self.flows.values()))[1] < t - 60:
            self.flows.popitem(last=False)
        response = reverse in self.flows
        flow_key = reverse if response else key
        actor = self.flows[flow_key][0] if flow_key in self.flows else packet.source_ip
        self.flows[flow_key] = (actor, t)
        self.flows.move_to_end(flow_key)
        if len(self.flows) > self.max_flows:
            self.flows.popitem(last=False)
            self.evictions += 1
        if actor not in self.sources:
            if len(self.sources) >= self.max_sources:
                self.sources.popitem(last=False)
                self.evictions += 1
            self.sources[actor] = deque(maxlen=self.max_events)
        events = self.sources[actor]
        if len(events) == self.max_events:
            self.evictions += 1
        # Metadata only; no payload retained. SYN+ACK response is evidence, not completed handshake.
        events.append((t, packet, response, flow_key))
        self.sources.move_to_end(actor)
        return rows

    def _snapshot(self, t):
        rows = []
        for actor, events in list(self.sources.items()):
            while events and events[0][0] < t - self.window:
                events.popleft()
            if not events:
                del self.sources[actor]
                continue
            outgoing = [e for e in events if not e[2]]
            syns = {e[3] for e in outgoing if 'SYN' in e[1].tcp_flags and 'ACK' not in e[1].tcp_flags}
            synacks = {e[3] for e in events if e[2] and {'SYN', 'ACK'} <= set(e[1].tcp_flags)}
            acks = {e[3] for e in outgoing if 'ACK' in e[1].tcp_flags and 'SYN' not in e[1].tcp_flags}
            completed = acks & syns & synacks
            # Only model missing pairs for SYN flows without observed replies,
            # ACKs or resets, and with room inside the observed time span.
            replies = {e[3] for e in events if e[2]}
            resets = {e[3] for e in events if 'RST' in e[1].tcp_flags}
            early_syns = {e[3] for e in outgoing if 'SYN' in e[1].tcp_flags
                          and 'ACK' not in e[1].tcp_flags and e[0] < events[-1][0]}
            repairable = (syns & early_syns) - replies - acks - resets
            n = len(events)
            values = [n, sum(e[1].packet_size for e in events)/self.window,
                      len({e[1].destination_port for e in outgoing if e[1].destination_port is not None}),
                      len({e[1].destination_ip for e in outgoing}),
                      sum('SYN' in e[1].tcp_flags and 'ACK' not in e[1].tcp_flags for e in outgoing)/self.window,
                      sum('RST' in e[1].tcp_flags for e in events)/n,
                      sum(e[2] for e in events)/n,
                      sum(e[1].packet_size for e in events)/n,
                      sum(e[1].protocol == 'UDP' for e in events)/n,
                      sum(e[1].protocol == 'ICMP' for e in events)/n,
                      (events[-1][0]-events[0][0])/max(n-1, 1),
                      len(completed)/max(len(syns), 1)]
            rows.append({'timestamp': t, 'source': actor, 'features': dict(zip(FEATURES, values)),
                         'graph_context': {
                             'out_degree': len({e[1].destination_ip for e in outgoing}),
                             'edges': sorted({f'{e[1].destination_ip}|{e[1].destination_port}|{e[1].protocol}' for e in outgoing})[:256],
                             'edges_truncated': len({(e[1].destination_ip, e[1].destination_port, e[1].protocol) for e in outgoing}) > 256,
                         },
                         'traffic_context': {
                             'destination_ip': outgoing[-1][1].destination_ip if outgoing else None,
                             'protocol': outgoing[-1][1].protocol if outgoing else events[-1][1].protocol,
                         },
                         'handshake_context': {'syn_flows': len(syns), 'completed_flows': len(completed),
                                               'repairable_flows': len(repairable), 'window_seconds': self.window},
                         'quality': {'state_evictions': self.evictions, 'late_packets': self.late_packets,
                                     'capture_loss': 'unknown'}})
        return rows

    def finish(self):
        return self.advance(self.next_tick) if self.next_tick is not None else []
