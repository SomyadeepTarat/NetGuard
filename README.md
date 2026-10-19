# NetGuard v0.1

A terminal-based real-time network traffic analyser: the first 25% milestone of NetGuard. Captures packets with Scapy, extracts metadata, and maintains basic statistics. Intrusion detection, persistence, and a browser dashboard are future milestones.

## Setup

Requires Python 3.10 or newer.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
python -m backend.main --list-interfaces
python -m backend.main --interface en0
```

Run commands from the project root. Choose an interface from the list; omit `--interface` to use Scapy's route-selected default. Interface names vary (`en0` on macOS, `eth0` on Linux). Live capture requires permission to access the interface. On macOS/Linux, if access is denied, run using the virtual environment interpreter:

```sh
sudo .venv/bin/python -m backend.main --interface en0
```

On Windows, install Npcap and run an administrator terminal. BPF filtering requires libpcap/Npcap:

```sh
python -m backend.main --interface en0 --filter 'tcp or udp' --refresh 0.5
```

Only monitor networks and interfaces you are authorized to monitor. No payloads are persisted by NetGuard. Captured addresses and ports still contain sensitive metadata.

## Monitor

Displays status, interface, total packets/bytes, protocol counters, average packets/sec and bytes/sec since startup, and the most recent 15 packet records. Each record contains a local timestamp, IPv4 endpoints, TCP/UDP ports, frame size in bytes, and TCP flags. Ctrl+C stops capture and displays final statistics.

IPv4 TCP, UDP, and ICMP are identified; ARP, IPv6, unsupported frames, and malformed packets are classified as OTHER. ICMP and OTHER ports are absent. Encapsulated transport headers are not mistaken for the outer protocol. Packet timestamps come from Scapy with a current-time fallback. Frame size is the bytes available to Scapy, not necessarily full wire size when capture is truncated.

Scapy uses `store=False`; only 15 immutable metadata records are retained. Statistics and snapshots are synchronized between capture and display threads. Rates are session averages. One malformed packet does not end capture. Capture startup errors are reported with a nonzero exit status.

## Replay and tests

Replay an existing PCAP without live capture privileges (processed as quickly as possible, not at original timing):

```sh
python -m backend.main --pcap traffic.pcap
python -m unittest discover -s tests -v
```

Tests construct packets locally and verify parsing, flags, unsupported inputs, exact byte counts, counters, rates, bounded metadata history, interface validation, and a full PCAP capture-to-analysis pipeline. Live capture depends on OS permissions and must also be checked on the target interface: start monitoring, generate traffic, confirm counters increase, then press Ctrl+C.

## Structure

- `backend/capture/packet_capture.py`: interface discovery and capture lifecycle.
- `backend/analyzer/packet_parser.py`: metadata extraction.
- `backend/analyzer/traffic_analyzer.py`: counters, rates, bounded history.
- `backend/models/packet.py`: immutable packet metadata.
- `backend/main.py`: terminal CLI and refresh loop.
- `tests/`: parser, statistics, and capture integration tests.
