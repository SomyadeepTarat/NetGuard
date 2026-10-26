from scapy.all import AsyncSniffer, conf
from backend.analyzer.packet_parser import parse_packet
from threading import Event
from time import monotonic


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
        self._offline = bool(pcap)

    def start(self):
        if self._offline:
            self.sniffer.start()
            return
        ready = Event()
        self.sniffer.kwargs['started_callback'] = ready.set
        self.sniffer.start()
        deadline = monotonic() + 3.0
        while not ready.wait(0.05):
            error = getattr(self.sniffer, 'exception', None)
            if error:
                raise error
            if monotonic() >= deadline:
                try:
                    self.stop()
                finally:
                    raise RuntimeError('Capture backend did not become ready within 3 seconds')

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
