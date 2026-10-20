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

## ML milestone: train, replay, and stream

The ML pipeline is implemented for **BENIGN**, **PORT_SCAN**, **SYN_FLOOD**, and **TRAFFIC_FLOOD**. A traffic flood is a sustained high-volume pattern; a learned-baseline traffic-spike detector is not implemented. This classifier predicts likely patterns, not confirmed compromises. It cannot identify all attacks from headers alone.

Install dependencies in the existing environment:

```sh
.venv/bin/python -m pip install -r backend/requirements.txt
```

### Working local demonstration

The generator writes synthetic PCAPs locally; it never sends packets to a network. Train on separate sessions, select the score threshold on validation sessions, and evaluate on held-out test sessions:

```sh
.venv/bin/python -m backend.ml demo-data --sessions 4
.venv/bin/python -m backend.ml train --manifest artifacts/demo/manifest.json
.venv/bin/python -m backend.ml predict --pcap artifacts/demo/test-PORT_SCAN-0.pcap --output artifacts/scan-predictions.jsonl
.venv/bin/python -m backend.main --pcap artifacts/demo/test-SYN_FLOOD-0.pcap --model artifacts/netguard.joblib --predictions artifacts/replay.jsonl --refresh 1
```

Generated artifacts (ignored by Git):

- `artifacts/netguard.joblib`: fitted random forest and versioned feature schema.
- `artifacts/netguard.report.json`: baseline versus ML precision/recall/F1, confusion matrices, false alerts per benign observation hour, detection delays, and inference throughput, at 0%, 10%, and 30% randomly injected packet loss.
- `artifacts/*.jsonl`: predictions, scores, feature evidence, and quality indicators.

**Synthetic results only establish that the pipeline works.** The demo's classes are deliberately simplified; strong scores do not establish deployment accuracy. No public attack dataset has been downloaded or independently validated. Scores are uncalibrated classifier outputs, not probabilities that a real threat exists. Do not use this demo model for automatic blocking.

### Live ML monitoring

```sh
sudo .venv/bin/python -m backend.main --interface en0 --model artifacts/netguard.joblib --predictions artifacts/live.jsonl
```

Live capture hands metadata to a bounded queue without waiting for inference. A separate worker computes rolling **5-second** source-behavior windows at **1-second** intervals, scores them, and writes JSONL. The terminal shows recent predictions. `alert=true` is issued for sufficiently scored suspicious predictions with a 10-second per-source/class cooldown. Every scored window is still written to the output, including uncertain and benign windows. Output files grow continuously; rotate/delete them according to your retention needs.

PCAP replay uses packet timestamps, not processing speed. The queue applies backpressure for offline replay to avoid silently losing training/demo events. Shutdown stops capture and drains queued metadata before emitting the final snapshot. Throughput and detection delay depend on traffic and hardware; one-second scheduling is not a guaranteed one-second detection time.

### Feature extraction and limits

Live capture, training, and replay use the same `FeatureExtractor`. Features include packet count, byte rate, distinct destination ports/hosts, SYN rate, RST fraction, response fraction, mean size, UDP/ICMP fractions, mean interarrival gap, and an observed handshake fraction. No IP address or exact port identity is fed into the model.

Flows are oriented by first observation. Matching reverse tuples attribute replies to the initiating actor. Handshake evidence requires an observed SYN, reverse SYN+ACK, and outgoing ACK in the window; this is a heuristic, not TCP sequence-number validation or proof of successful authentication. Midstream capture, asymmetric routing, NAT, and reused tuples can impair interpretation. IPv4 is the current supported scope.

State is bounded to 256 source histories, 4,096 events per source, and 20,000 oriented flow records. Event histories expire after five seconds; orientation records expire on packet processing after 60 seconds of inactivity. Late packets are discarded from feature extraction and counted. State evictions, late events, and queue drops are reported. Suspicious results become `UNCERTAIN` after recorded state loss. These counters are conservative/cumulative for the run.

Kernel/NIC capture-drop telemetry and asymmetric-visibility verification are **not yet implemented**: `capture_loss` remains `unknown`. The system must not claim that a missing ACK proves an attack. Injected packet-loss evaluation measures robustness; it does not reconstruct missing evidence or guarantee false-alarm elimination.

### Bring your own labeled sessions

Create a JSON manifest with separate PCAP captures for train, validation, and test. Each capture currently needs one session-wide label; an optional `source` field restricts evaluation/training to that labeled actor (used in the demo to avoid mislabeling orphaned victim replies as attacks); split mixed captures into labeled intervals/PCAPs before importing. Example record:

```json
{"session": "lab-day1-scan", "split": "train", "label": "PORT_SCAN", "pcap": "lab-day1-scan.pcap", "scope": "authorized-lab"}
```

The manifest is an array of these records. PCAP paths are relative to the manifest. All four classes are required in training. Use representative benign captures from the target environment, including downloads, streaming, backups, and failed connections. Keep entire days/devices/experiments in one split; never split neighboring windows randomly. The importer rejects repeated session names and repeated capture paths, but cannot establish that differently named files came from independent experiments.

```sh
.venv/bin/python -m backend.ml train --manifest /absolute/path/manifest.json --model artifacts/lab-model.joblib
```

Existing CICFlowMeter CSV columns are not automatically interchangeable with these features. Import raw labeled PCAPs through this extractor, or implement a separately versioned matching feature adapter. Load only trusted model files: joblib deserialization can execute code.

### Future extension points

Feature extraction, classification, rule evidence, quality indicators, and streaming output are separate modules. This leaves room for future capture-quality-aware verification and evidence selection without treating those proposed research features as already implemented. Online retraining, anomaly detection for unknown attacks, calibration, endpoint-log correlation, and a web dashboard remain future work.
