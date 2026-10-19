from scapy.all import AsyncSniffer, conf
from backend.analyzer.packet_parser import parse_packet


def list_interfaces():
    return list(conf.ifaces.values())


def resolve_interface(name=None):
    if name is None:
        return conf.iface
    for interface in list_interfaces():
        if name in (interface.name, interface.description, interface.network_name):
            return interface
    raise ValueError(f"Unknown interface: {name}. Use --list-interfaces.")


class PacketCapture:
    def __init__(self, analyzer, interface=None, pcap=None, capture_filter=None):
        options = {"store": False, "prn": lambda packet: analyzer.process(parse_packet(packet))}
        if pcap:
            options["offline"] = pcap
        else:
            options["iface"] = resolve_interface(interface)
        if capture_filter:
            options["filter"] = capture_filter
        self.sniffer = AsyncSniffer(**options)

    def start(self):
        self.sniffer.start()

    def stop(self):
        if self.sniffer.running:
            self.sniffer.stop()
        else:
            self.sniffer.join()

    def check(self):
        error = getattr(self.sniffer, "exception", None)
        if error:
            raise error
        return self.sniffer.running
