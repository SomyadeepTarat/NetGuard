"""Generate local PCAPs only. Never transmit attack traffic."""
import json
import random
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def generate(directory, sessions=8):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = []
    for split, offset in [('train', 0), ('validation', 100), ('test', 200)]:
        for category in ('BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'):
            for session in range(sessions):
                rng = random.Random(offset + session)
                start = 1700000000 + (offset + session)*100
                src, dst = f'10.0.{offset//100}.{session+1}', '192.168.1.10'
                packets = []
                def add(t, layer, response=False, payload=0):
                    p = Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:02')/IP(src=dst if response else src, dst=src if response else dst)/layer
                    if payload:
                        p = p/Raw(b'x'*payload)
                    p.time = start+t
                    packets.append(p)
                for second in range(12):
                    if category == 'BENIGN':
                        # Normal sessions include bulk downloads and failed connections.
                        for i in range(rng.randint(3, 16)):
                            t = second + i/20
                            port = 40000+i
                            add(t, TCP(sport=port, dport=443, flags='S'))
                            if rng.random() > .12:
                                add(t+.005, TCP(sport=443, dport=port, flags='SA'), True)
                                add(t+.01, TCP(sport=port, dport=443, flags='A'))
                                add(t+.015, TCP(sport=443, dport=port, flags='PA'), True, rng.randint(100, 1400))
                        add(second+.95, UDP(sport=53000, dport=53))
                        add(second+.96, UDP(sport=53, dport=53000), True, 100)
                    elif category == 'PORT_SCAN':
                        for i in range(rng.randint(15, 35)):
                            port = second*40+i+20
                            add(second+i/50, TCP(sport=45000, dport=port, flags='S'))
                            if rng.random() < .4:
                                add(second+i/50+.002, TCP(sport=port, dport=45000, flags='R'), True)
                    elif category == 'SYN_FLOOD':
                        for i in range(rng.randint(90, 150)):
                            add(second+i/200, TCP(sport=20000+second*200+i, dport=80, flags='S'))
                    else:
                        for i in range(rng.randint(100, 150)):
                            add(second+i/200, UDP(sport=45000, dport=9000), payload=rng.randint(900, 1400))
                packets.sort(key=lambda p: p.time)
                name = f'{split}-{category}-{session}.pcap'
                wrpcap(str(directory/name), packets)
                manifest.append({'session': name[:-5], 'split': split, 'label': category,
                                 'pcap': name, 'source': src, 'scope': 'synthetic-demo'})
    path = directory/'manifest.json'
    path.write_text(json.dumps(manifest, indent=2))
    return path
