from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PacketInfo:
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_size: int
    tcp_flags: tuple[str, ...] = ()
