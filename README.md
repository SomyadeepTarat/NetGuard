# NetGuard: Evidence-Aware Network Threat Observatory
### With Evidence Resilience Engine (ERE) & Offline Evidence Resilience Studio

### Experimental observation-aware fusion extension

The supervised classifier is now a **calibrated RBF-kernel SVM**, and the auxiliary
anomaly detector is **Local Outlier Factor in novelty mode**. Both use log1p and
robust feature scaling. The SVM is trained using capture-grouped sigmoid calibration
and a separate validation threshold. Retrain old model artifacts before use:

```powershell
.\.venv\Scripts\python.exe -m backend.ml demo-data --directory artifacts/demo --sessions 8
.\.venv\Scripts\python.exe -m backend.ml train --manifest artifacts/demo/manifest.json --model artifacts/netguard.joblib
```

The web pipeline now measures the same rolling source-window features used by
offline analysis. A new research branch combines robust log/MAD preprocessing,
Ledoit-Wolf multivariate distance, frozen peer/service-edge novelty, empirical
split-conformal calibration, per-source CUSUM corroboration and a visibility
sensitivity intervention. It runs alongside the existing rules and non-tree models.
This is a proposed research integration; priority and real-world superiority have
not been established. See [the method, formulas, assumptions and evaluation protocol](docs/evidence_fusion.md).

**Source selection:** server startup defaults to automatic live capture when an
active adapter and usable capture backend exist. Otherwise it replays a configured
dataset PCAP and periodically retries live capture. The source and fallback reason
are visible. If no real dataset has been supplied, synthetic fixtures remain clearly
labeled as synthetic.

```powershell
# Put an authorized dataset PCAP inside artifacts/datasets/ first.
$env:NETGUARD_MODE = "auto"
$env:NETGUARD_DATASET_PCAP = "artifacts/datasets/network.pcap"
.\.venv\Scripts\python.exe -m backend.main --server

# Reproducible mechanism checks and component ablations (synthetic features).
.\.venv\Scripts\python.exe -m backend.ml.evaluate_fusion
# Use independently labelled PCAP sessions for real dataset evaluation instead:
.\.venv\Scripts\python.exe -m backend.ml.evaluate_fusion --manifest artifacts/datasets/manifest.json
```

The new evidence appears on Overview and in incident passports. Model Evaluation
shows branch ablations against rules, RBF-kernel SVM and novelty-mode Local Outlier Factor. Optional
`NETGUARD_FUSION_REFERENCE` loads a frozen reference bundle produced by the evaluator.
The server reads actual shell environment variables; `.env.example` documents them.
Synthetic reference bundles are not used for live sessions.

Offline mode keeps the project's existing synthetic PCAP dataset. The new branch
builds its demonstration reference from BENIGN TRAIN/VALIDATION captures and
excludes TEST captures; its overlapping-window scope is shown explicitly. That
synthetic reference is discarded when transitioning to actual LIVE capture.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-109%20Passed-brightgreen.svg)](#7-automated-test-suite)
[![License](https://img.shields.io/badge/License-Academic%20Advisory-green.svg)](#8-ethics-privacy--safety-boundaries)

---

## 1. Research Mission & Novelty Contribution

NetGuard is an **advisory, read-only Network Threat Observatory** designed for computer network security analysis, flow monitoring, and research into detection robustness under real-world observation failures.

Standard Network Intrusion Detection Systems (NIDS) report categorical threat labels while assuming perfect, lossless observation. In reality, monitors drop packets due to kernel queue saturation, NIC ring-buffer exhaustion, or asymmetric routing (*Computer Communications*, 2026).

NetGuard introduces the **Evidence Resilience Engine (ERE)**, uniting three tightly coupled capabilities into a cohesive investigation workflow:

1. **Observation Robustness Atlas:** Systematically measures how incident decisions change under a reproducible matrix of controlled observation failures (Random Loss across seed ensembles, Burst Loss, and Directional Visibility Loss), with exact packet accounting (Source, Omitted, Retained) and canonical `(source, timestamp)` time-window alignment.
2. **Passive Next-Observation Planner:** Converts observed telemetry gaps (e.g., unavailable kernel counters, queue drops, directional flips) into a ranked, explainable list of additional passive observations or checks that reduce investigative uncertainty, without transmitting network packets or taking active actions (`active_network_action: false`).
3. **Tamper-Evident Evidence Lineage:** Cryptographic provenance tracking linking the original incident, source-capture fingerprint, parser/feature/model configuration, and robustness experiment through RFC 8785 canonical JSON manifests and an append-only SQLite SHA-256 hash chain with genesis block linkage.

### Academic Honesty & Scope Guarantees
- **No Pretend Live Capture:** Offline/synthetic sessions are visibly labeled `DEMO / SYNTHETIC`. Synthetic traffic is never disguised as live enterprise capture.
- **Strictly Advisory & Read-Only:** NetGuard never transmits packets, attacks remote endpoints, injects firewall rules, or automatically blocks IP addresses.
- **The Non-Mutation Guarantee:** Robustness sweeps and planner outputs append child findings. They **never mutate, rewrite, suppress, or delete** original incident records in the Evidence Passport repository.
- **Honest Capture Telemetry:** Missing OS/driver statistics are represented as `UNKNOWN` or `UNAVAILABLE`—never faked as "0% packet loss".
- **Bounded Stability Claims:** Decisions are reported as "Stable within tested parameter space"—never as universal zero-day guarantees.

---

## 2. System Architecture

```mermaid
graph TD
    A[Traffic Source: Scapy Live / Offline PCAP / Deterministic Demo] --> B[Multi-Protocol Packet Parser]
    B -->|IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS| C[Bounded Bidirectional Flow Engine]
    C --> D[1s / 5s Rolling Traffic Telemetry]
    
    C --> E[Tri-Pillar Threat Detection Engine]
    E --> E1[Explainable Rule Engine: SYN, Port Sweep, Floods]
    E --> E2[Known-Pattern Classifier: RBF-kernel SVM 4-Class]
    E --> E3[Anomaly Detector: novelty-mode Local Outlier Factor + Baseline Warm-Up]
    
    C --> F[Capture Quality Telemetry]
    F -->|HEALTHY, DEGRADED, UNKNOWN, UNAVAILABLE| G[Evidence Fusion Engine]
    E1 & E2 & E3 & F --> G
    
    G --> H[(SQLite Evidence Passport Repository)]
    H --> I[FastAPI REST API + SSE Real-Time Stream]
    I --> J[React + TypeScript Workstation Console]
    
    K[Offline PCAP Fixture] --> L[Evidence Resilience Engine ERE]
    L --> L1[Robustness Atlas: Multi-Scenario Matrix]
    L --> L2[Passive Next-Observation Planner: Rule Triage]
    L --> L3[Tamper-Evident Lineage: Append-Only Hash Chain]
    L1 & L2 & L3 --> I
```

---

## 3. Quickstart & Installation

### 3.1 Prerequisites
- **Python 3.10+**
- **Node.js 18+** and **npm**
- Windows (PowerShell), Linux, or macOS. Offline replay needs no capture driver or cloud API keys. Live capture requires a working capture backend (Npcap on Windows) and appropriate local privileges.

### 3.2 Backend Setup
```powershell
# 1. Clone repository and navigate to directory
cd "NetGuard-main"

# 2. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 3. Install backend dependencies (if needed)
python -m pip install -r backend/requirements.txt
```

### 3.3 Frontend Compilation
```powershell
cd frontend
npm install
npm run build
cd ..
```

---

## 4. Running the Observatory

### Option A: Complete Web Observatory (Recommended)
Launch the unified FastAPI server hosting both the REST API and the compiled React workstation console on port 8000:

```powershell
.\.venv\Scripts\python.exe -m backend.main --server --host 127.0.0.1 --port 8000
```
Open **`http://localhost:8000`** in any modern web browser.

### Option B: Generating Research Evidence Artifacts
Execute the automated ERE research runner to run a 25-scenario sweep, generate passive triage recommendations, verify the hash chain, and export reproducible JSON bundles into `artifacts/research/`:

```powershell
.\.venv\Scripts\python.exe -m backend.scripts.generate_research_evidence
```

---

## 5. Web Console Surfaces & Evidence Resilience Studio

| Navigation Area | Description |
|---|---|
| **Overview** | Real-time packets/sec, bytes/sec, active hosts/flows, protocol distribution (TCP/UDP/ICMP/ARP/DNS), recent incident feed, and capture quality status. |
| **Flows & Traffic** | Bounded bidirectional flow table (5-tuples), directional packet/byte accounting, duration, observed TCP flags, and pagination. |
| **Host Explorer** | Interactive SVG-rendered communication relationship graph with host inspection drawers. |
| **Alerts & Evidence** | Searchable incidents with the **Evidence Passport**: explainable rule triggers, uncalibrated classifier score, anomaly baseline readiness, and non-destructive investigation steps. |
| **Replay Lab / Evidence Resilience Studio** | Four specialized sub-surfaces:<br>• **Single Replay:** Baseline vs. single perturbation comparison.<br>• **Robustness Atlas:** Sweep matrix builder, heatmap table, instability boundary, and feature drift.<br>• **Next Observation:** Ranked, explainable passive triage recommendations citing real telemetry gaps (`active_network_action: false`).<br>• **Evidence Lineage:** Cryptographic hash-chain verifier (`VALID`/`INVALID`), manifest inspector, and one-click JSON Evidence Bundle export. |
| **Model Evaluation** | Held-out test evaluation report: per-class Precision/Recall/F1, Macro-F1, confusion matrix, false alerts per benign hour, detection latency, and throughput. |
| **Settings & Reports** | Download full Evidence Passports as JSON or CSV. Includes one-click **IP Address Pseudonymization** for privacy compliance. |

---

## 6. Additive ERE / Lens API Surface

All new research capabilities are exposed through dedicated, typed, backwards-compatible endpoints under `/api/lens/`:

- `POST /api/lens/robustness-runs` — Create bounded sweep run with safe PCAP ID, loss profiles, and seeds.
- `GET /api/lens/robustness-runs` — List all recent sweep runs and execution statuses.
- `GET /api/lens/robustness-runs/{run_id}` — Inspect sweep progress, atlas matrix, and robustness envelope.
- `POST /api/lens/robustness-runs/{run_id}/cancel` — Gracefully request cancellation of an active sweep.
- `GET /api/lens/robustness-runs/{run_id}/report` — Retrieve reproducible JSON robustness report.
- `GET /api/lens/alerts/{alert_id}/observation-plan` — Generate explainable passive follow-up plan for an incident.
- `GET /api/lens/lineage/verify` — Independently recompute and verify SQLite evidence hash chain.
- `GET /api/lens/lineage/events` — Paginated list of append-only lineage manifests.
- `GET /api/lens/lineage/{event_id}` — Retrieve full canonical JSON manifest for an event block.
- `GET /api/lens/evidence-bundle/{id}` — Download reproducible Evidence Bundle uniting incident, sweep, and lineage.

---

## 7. Automated Test Suite

Run the complete regression suite covering packet parsing, flow tracking, capture quality, threat detection, PCAP path isolation, sweep matrix orchestration, planner determinism, and hash-chain tamper detection:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

**Latest local results:** `109 passed, 0 skipped, 0 failed` in 10.57 seconds, with the SVM artifact trained on the existing synthetic PCAP dataset. One dependency deprecation warning concerns Starlette's HTTPX test client. Development dependencies are listed in `backend/requirements-dev.txt`.

---

## 8. Ethics, Privacy & Safety Boundaries

- **Passive & Advisory:** NetGuard transmits zero packets and performs no active port scanning, ping sweeps, or automated host blocking.
- **Metadata Only:** Payloads are never captured, examined, or stored. Only packet headers, flow statistics, and DNS query names/types are processed.
- **Privacy Controls:** Host IP addresses can be pseudonymized in all generated incident reports and exported bundles.
- **Safe Path Resolution:** PCAP access is strictly constrained to authorized allowlisted project directories, rejecting directory traversal sequences (`..`), non-pcap extensions, and paths outside allowed roots.
- **Tamper Evidence:** SHA-256 hash chains detect in-place modification of recorded incidents and experiments within application storage; they do not represent global blockchain infrastructure or protection against hostile disk destruction.
