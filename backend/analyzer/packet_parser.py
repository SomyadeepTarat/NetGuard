from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP
from backend.models.packet import PacketInfo

FLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
         (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
         (0x40, "ECE"), (0x80, "CWR"), (0x100, "NS"))


def parse_packet(packet) -> PacketInfo:
    """Extract metadata only; unsupported or malformed frames become OTHER."""
    timestamp = datetime.now().astimezone()
    size = 0
    source = destination = None
    try:
        timestamp = datetime.fromtimestamp(float(packet.time)).astimezone()
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
        pass
    try:
        size = len(packet)
        if IP not in packet:
            return PacketInfo(timestamp, None, None, None, None, "OTHER", size)
        ip = packet[IP]
        source, destination = str(ip.src), str(ip.dst)
        # Inspect the direct IPv4 payload, not nested/tunnel transport layers.
        transport = ip.payload
        if isinstance(transport, TCP):
            flags = tuple(name for bit, name in FLAGS if int(transport.flags) & bit)
            return PacketInfo(timestamp, source, destination, int(transport.sport),
                              int(transport.dport), "TCP", size, flags)
        if isinstance(transport, UDP):
            return PacketInfo(timestamp, source, destination, int(transport.sport),
                              int(transport.dport), "UDP", size)
        if isinstance(transport, ICMP):
            return PacketInfo(timestamp, source, destination, None, None, "ICMP", size)
    except Exception:
        # A bad individual frame must never terminate the capture session.
        pass
    return PacketInfo(timestamp, source, destination, None, None, "OTHER", size)
