# NetGuard Security & Privacy Architecture

## 1. Security Posture & Advisory Scope

NetGuard is designed from the ground up as a **passive, advisory, read-only Network Threat Observatory**. 

### 1.1 Strictly Passive Operations
- **No Active Packet Transmission:** NetGuard does not send probe frames, spoof packets, transmit exploits, or interact with monitored endpoints.
- **No Automated Remediation / Blocking:** NetGuard never modifies OS firewall rules, issues iptables/nftables drop commands, or resets TCP connections. All findings are presented strictly as advisory intelligence for human analysts.
- **Authorized Monitoring Boundaries:** Live network capture must be restricted exclusively to network interfaces and traffic streams that the operator is legally and organizationally authorized to inspect.

---

## 2. Data Privacy & Storage Policies

### 2.1 Metadata-Only Architecture
- **Zero Raw Payload Retention:** NetGuard records only protocol headers, flow 5-tuples, packet/byte counters, TCP control flags, and DNS transaction metadata (query type, query name, response code).
- **No Deep Packet Inspection (DPI) of Encrypted Data:** NetGuard explicitly respects encrypted transport channels (TLS, DoH, DoT) and does not attempt payload decryption or session interception.
- **Local SQLite Persistence:** Alerts and Evidence Passports are persisted locally in a structured SQLite database (`data/netguard.db` or configured path).

### 2.2 IP Pseudonymization & Redaction
- In accordance with privacy best practices, NetGuard provides an automated IP pseudonymization filter for incident exports and report generation:
  - IPv4 addresses: Masks host octets (e.g., `192.168.1.45` $\rightarrow$ `192.168.1.xxx`).
  - IPv6 addresses: Masks interface identifiers, retaining only network prefixes (e.g., `2001:db8::1` $\rightarrow$ `2001:db8:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx`).

---

## 3. Web Service & API Hardening

The FastAPI management backend enforces strict defensiveness:

### 3.1 Loopback-Only Binding by Default
- The HTTP server binds exclusively to `127.0.0.1` (localhost) by default.
- Binding to external interfaces (`0.0.0.0`) requires an explicit CLI parameter (`--host`) to prevent accidental LAN exposure of capture controls.

### 3.2 Scoped Cross-Origin Resource Sharing (CORS)
- CORS origins are restricted to local development addresses (`http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:8000`). Wildcard origins (`*`) are disallowed.

### 3.3 Path Traversal Defense
- The Replay Lab and PCAP ingestion endpoints disallow arbitrary filesystem paths.
- All file targets are sanitized and constrained to pre-approved directories (`artifacts/demo/` or user-configured capture roots).

### 3.4 Safe Model Deserialization
- Model loading is restricted to trusted local files specified during server launch or configuration.
- The web API **never** accepts arbitrary `joblib`, `pickle`, or binary weights uploads over HTTP to prevent remote code execution (RCE).

---

## 4. Resource Bounding & Denial-of-Service Defense

To ensure that the monitoring platform itself remains resilient under high packet volumes:

1. **Non-Blocking Ingestion Queues:** The packet capture handoff uses a bounded queue (`maxsize=10,000`). If downstream analysis slows, excess packets are dropped with an explicit internal queue-drop counter rather than blocking the packet sniffer.
2. **Bounded Flow Tables:** The flow engine limits active sessions (`max_flows=10,000`). Inactive flows are evicted on idle timeout (60s) or TCP completion (FIN/RST).
3. **Bounded Timeseries Ring Buffers:** Historical rate metrics are stored in fixed-size deque structures (300 points) to guarantee constant memory usage.
4. **Replay Experiment Limits:** Replay Lab simulations run as isolated background threads with enforced execution timeouts and bounded memory buffers.
