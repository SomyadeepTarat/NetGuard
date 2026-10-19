from collections import deque
from threading import Lock
from time import monotonic
from backend.models.packet import PacketInfo


class TrafficAnalyzer:
    def __init__(self, recent_limit=15, clock=monotonic):
        self._clock = clock
        self._started = clock()
        self._lock = Lock()
        self._recent = deque(maxlen=recent_limit)
        self._packets = self._bytes = 0
        self._protocols = dict.fromkeys(("TCP", "UDP", "ICMP", "OTHER"), 0)

    def process(self, packet: PacketInfo):
        with self._lock:
            self._packets += 1
            self._bytes += packet.packet_size
            self._protocols[packet.protocol if packet.protocol in self._protocols else "OTHER"] += 1
            self._recent.append(packet)

    def snapshot(self):
        with self._lock:
            elapsed = max(0, self._clock() - self._started)
            return {"total_packets": self._packets, "total_bytes": self._bytes,
                    "protocols": self._protocols.copy(), "elapsed": elapsed,
                    "packets_per_second": self._packets / elapsed if elapsed else 0,
                    "bytes_per_second": self._bytes / elapsed if elapsed else 0,
                    "recent": tuple(self._recent)}
