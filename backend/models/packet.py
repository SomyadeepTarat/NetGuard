from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class PacketInfo:
    """Immutable normalized metadata representation of a single observed network frame.
    
    No raw packet payload data is ever retained in memory or persisted.
    """
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_size: int
    tcp_flags: tuple[str, ...] = ()
    dns_query: str | None = None
    dns_qtype: str | None = None
    dns_rcode: int | None = None
    dns_is_response: bool | None = None
    arp_opcode: str | None = None
    arp_hwsrc: str | None = None
    arp_hwdst: str | None = None
    ip_version: int | None = None
    parser_error: str | None = None
