"""Extract metadata only; unsupported or malformed frames become OTHER.

Payload capture is explicitly disabled by default. No payload content is ever retained.
Encrypted transports (DoH/DoT) limit passive metadata visibility to transport headers.
"""
from datetime import datetime, timezone
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from backend.models.packet import PacketInfo

FLAGS = (
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
    (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
    (0x40, "ECE"), (0x80, "CWR"), (0x100, "NS")
)

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"
}


def _extract_dns(packet) -> dict:
    """Safely inspect visible DNS metadata without payload retention.
    
    Limitation: DNS-over-HTTPS (DoH, port 443) and DNS-over-TLS (DoT, port 853)
    encrypt application payloads, preventing passive DNS metadata inspection.
    """
    dns_meta = {}
    try:
        if DNS in packet:
            dns = packet[DNS]
            dns_meta["dns_is_response"] = bool(getattr(dns, "qr", 0) == 1)
            dns_meta["dns_rcode"] = int(getattr(dns, "rcode", 0))
            qd_list = getattr(dns, "qd", None)
            qd = None
            if qd_list:
                try:
                    qd = qd_list[0]
                except (IndexError, TypeError):
                    qd = qd_list
            if qd is not None and hasattr(qd, "qname") and qd.qname:
                qname = qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                dns_meta["dns_query"] = str(qname).rstrip(".")
                qtype_val = getattr(qd, "qtype", None)
                if qtype_val is not None:
                    dns_meta["dns_qtype"] = DNS_QTYPES.get(int(qtype_val), str(qtype_val))
    except Exception:
        pass
    return dns_meta


def parse_packet(packet) -> PacketInfo:
    """Extract metadata only; unsupported or malformed frames become OTHER."""
    timestamp = datetime.now().astimezone()
    size = 0
    source = destination = None
    parse_error = None
    
    # 1. Normalize timestamp safely across Windows, Linux, and macOS.
    try:
        timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).astimezone()
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
        pass

    try:
        size = len(packet)
    except Exception:
        size = 0

    try:
        # 2. IPv4: Inspect direct transport payload, avoiding embedded tunnel/error layers
        if IP in packet:
            ip = packet[IP]
            source, destination = str(ip.src), str(ip.dst)
            transport = ip.payload
            dns_meta = _extract_dns(packet)

            if isinstance(transport, TCP):
                flags = tuple(name for bit, name in FLAGS if int(transport.flags) & bit)
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=int(transport.sport), destination_port=int(transport.dport),
                    protocol="TCP", packet_size=size, tcp_flags=flags,
                    ip_version=4, **dns_meta
                )
            if isinstance(transport, UDP):
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=int(transport.sport), destination_port=int(transport.dport),
                    protocol="UDP", packet_size=size,
                    ip_version=4, **dns_meta
                )
            if isinstance(transport, ICMP):
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=None, destination_port=None,
                    protocol="ICMP", packet_size=size, ip_version=4
                )
            return PacketInfo(
                timestamp=timestamp, source_ip=source, destination_ip=destination,
                source_port=None, destination_port=None,
                protocol="OTHER", packet_size=size, ip_version=4
            )

        # 3. IPv6
        if IPv6 in packet:
            ip6 = packet[IPv6]
            source, destination = str(ip6.src), str(ip6.dst)
            transport = ip6.payload
            dns_meta = _extract_dns(packet)

            if isinstance(transport, TCP):
                flags = tuple(name for bit, name in FLAGS if int(transport.flags) & bit)
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=int(transport.sport), destination_port=int(transport.dport),
                    protocol="TCP", packet_size=size, tcp_flags=flags,
                    ip_version=6, **dns_meta
                )
            if isinstance(transport, UDP):
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=int(transport.sport), destination_port=int(transport.dport),
                    protocol="UDP", packet_size=size,
                    ip_version=6, **dns_meta
                )
            if isinstance(transport, _ICMPv6):
                return PacketInfo(
                    timestamp=timestamp, source_ip=source, destination_ip=destination,
                    source_port=None, destination_port=None,
                    protocol="ICMPv6", packet_size=size, ip_version=6
                )
            return PacketInfo(
                timestamp=timestamp, source_ip=source, destination_ip=destination,
                source_port=None, destination_port=None,
                protocol="OTHER", packet_size=size, ip_version=6
            )

        # 4. ARP
        if ARP in packet:
            arp = packet[ARP]
            op_code = "who-has" if int(arp.op) == 1 else ("is-at" if int(arp.op) == 2 else str(arp.op))
            return PacketInfo(
                timestamp=timestamp,
                source_ip=str(arp.psrc),
                destination_ip=str(arp.pdst),
                source_port=None,
                destination_port=None,
                protocol="ARP",
                packet_size=size,
                arp_opcode=op_code,
                arp_hwsrc=str(arp.hwsrc),
                arp_hwdst=str(arp.hwdst)
            )

    except Exception as error:
        parse_error = str(error)

    # 5. Unsupported, non-IP, or malformed frames fall back safely to OTHER
    return PacketInfo(
        timestamp=timestamp, source_ip=source, destination_ip=destination,
        source_port=None, destination_port=None,
        protocol="OTHER", packet_size=size, parser_error=parse_error
    )
