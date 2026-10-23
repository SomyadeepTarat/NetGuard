# NetGuard Implementation Plan & Acceptance Tracking
**Evidence-Aware Network Threat Observatory with Capture-Aware Incident Verification**

## Baseline Audit & Initial Environment Status
- **Environment**: Windows 11 / PowerShell, Python 3.12.4, Node.js v24.15.0, npm 11.12.1.
- **Git Status**: Workspace extracted without a `.git` folder (`fatal: not a git repository`). User files preserved intact.
- **Initial Test Suite Run**:
  - `python -m unittest discover -s tests -v`: Failed with 5 errors due to missing dependencies in global environment.
  - Dependencies installed into dedicated virtual environment `.venv`: `scapy>=2.6`, `scikit-learn>=1.5`, `joblib>=1.4`, plus `fastapi`, `uvicorn`, `pydantic`, `pytest`, `httpx`.
  - Re-run test suite in `.venv`:
    - Total tests: 22 (10 passed, 2 skipped, 2 failed, 8 errors).
    - Root Cause 1: Windows C runtime `localtime()` raises `OSError: [Errno 22] Invalid argument` in `datetime.fromtimestamp(100)` when no timezone is supplied, causing fallback to `datetime.now()` in `packet_parser.py`, throwing out-of-order errors and causing `advance(101)` in `test_ml` and `test_fragility` to miss window bounds. Resolved with `datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()`.
    - Root Cause 2: Scapy `Ether()` without arguments triggers loopback interface MAC resolution on Windows which errors when WinPcap/Npcap isn't installed. Resolved in test fixtures by supplying explicit dummy MAC addresses.

---

## Phase Checklist & Execution Status

### Phase 1 — Stabilize and Preserve Existing Engine
- [x] Baseline audit recorded in `docs/implementation_plan.md` and `docs/architecture.md`.
- [x] Fix Windows-specific datetime epoch handling in `packet_parser.py` (`fromtimestamp(..., tz=timezone.utc).astimezone()`).
- [x] Stabilize `test_capture.py` default Ethernet MAC on Windows non-Npcap environments.
- [x] Verify 100% of existing tests pass in `.venv` (22/22 baseline tests pass).
- [x] Preserve CLI interface in `backend/main.py` (`--interface`, `--pcap`, `--list-interfaces`, `--filter`, `--model`, `--predictions`, `--server`).
- [x] Add explicit logging configuration.

### Phase 2 — Network Visibility and Flow Analysis
- [x] Extend packet normalization: IPv6, ICMPv6, ARP semantics, DNS query/reply metadata tracking.
- [x] Handle unknown/unsupported protocol counters explicitly without failing.
- [x] Build bounded `FlowEngine`: bidirectional flow keying (canonical client/server orientation), duration, directional packet/byte counts, observed TCP flags.
- [x] Compute rolling throughput metrics (1s, 5s, 30s) and protocol distribution.
- [x] Track host communication graph (observed communication pairs only, explicitly not physical topology).
- [x] Unit tests for multi-protocol parsing, flow tracking, and graph generation in `tests/test_packet_parser.py` and `tests/test_flow_engine.py`.

### Phase 3 — Capture Quality and Observability Subsystem
- [x] Create `CaptureQualityService`: track OS/libpcap drops (where available), application queue drops, parser errors, out-of-order packets, flow evictions.
- [x] Status models: `HEALTHY`, `DEGRADED`, `UNKNOWN`, `UNAVAILABLE` with reason explanations.
- [x] Enforce distinction between live-measured loss, queue loss, and counterfactual simulated loss.
- [x] Unit tests for capture quality states and zero-drop / positive-drop / unknown reporting in `tests/test_capture_quality.py`.

### Phase 4 — Trustworthy Detection & Evidence Fusion
- [x] Preserve Random Forest 4-class model (`BENIGN`, `PORT_SCAN`, `SYN_FLOOD`, `TRAFFIC_FLOOD`) with feature schema validation.
- [x] Maintain transparent deterministic rules with feature thresholds and units.
- [x] Add benign baseline Anomaly Detector (Isolation Forest) with warm-up state and poison prevention (`backend/ml/anomaly.py`).
- [x] Evidence Fusion: present classifier score, rule decision, anomaly status, and capture quality side by side without an arbitrary black-box trust score.
- [x] Safe fallback when model is absent or not trained.
- [x] Unit tests in `tests/test_detection.py`.

### Phase 5 — Capture-Aware Incident Verification / Replay Lab
- [x] Refactor & enhance `backend/ml/replay.py` and `backend/ml/fragility.py`.
- [x] Deterministic PCAP Replay Lab supporting:
  - Baseline replay (0% loss).
  - Seeded random packet loss at variable rates.
  - Burst-loss periods (consecutive packet omissions).
  - Directional visibility loss.
- [x] Compare baseline vs perturbed runs side-by-side.
- [x] **Critical Guarantee**: Counterfactual experiments NEVER modify or overwrite original incident detections.
- [x] Exportable experiment artifacts with seeds, fingerprints, and software versions.
- [x] Unit tests in `tests/test_replay_lab.py` and `tests/test_fragility.py`.

### Phase 6 — Evidence Passport and Incident History (SQLite)
- [x] Implement thread-safe SQLite schema and repository in `backend/storage/repository.py` with `@contextmanager` connection management.
- [x] Persist Evidence Passports: alert ID, UTC timestamp, endpoints, flow stats, detector score, rule rationale, anomaly status, capture quality caveats, and safe next-steps.
- [x] Support JSON export, CSV export, and IP pseudonymization for privacy-safe reporting.
- [x] Unit tests in `tests/test_repository.py`.

### Phase 7 — FastAPI Service & Real-Time Event Delivery
- [x] Build typed FastAPI application with Pydantic v2 schemas:
  - `GET /api/health`
  - `GET /api/interfaces`
  - `POST /api/capture/start`, `POST /api/capture/stop`
  - `GET /api/overview`
  - `GET /api/traffic/timeseries`
  - `GET /api/flows`, `GET /api/hosts`
  - `GET /api/alerts`, `GET /api/alerts/{alert_id}`
  - `POST /api/replays`, `GET /api/replays/{run_id}`
  - `GET /api/evaluation`
  - `GET /api/events` (Server-Sent Events)
  - `GET /api/settings`
- [x] Bind to `127.0.0.1` by default; sanitize input paths to prevent directory traversal.
- [x] Serve compiled React static bundle from `frontend/dist/` at root URL.
- [x] Integration tests in `tests/test_api.py`.

### Phase 8 — Professional Frontend Console
- [x] Initialize React + TypeScript + Vite project in `frontend/`.
- [x] Design system: dark slate/graphite theme, cyan/blue accent, research badge accents, Lucide icons, accessible contrast.
- [x] Implement console views:
  - **Overview**: Live status, capture quality indicator, traffic rate telemetry, protocol distribution, recent alerts.
  - **Live Traffic / Flows**: Paginated flow table with directional details, TCP flags, duration, and search.
  - **Host Explorer**: Observed communication network graph with node inspector and alerts integration.
  - **Alerts & Evidence Passport**: Deep incident inspection, feature metrics, rule thresholds, uncalibrated score notice, and safe recommendations.
  - **Replay Lab**: Interactive counterfactual perturbation runner, baseline vs perturbed comparisons, and past runs history.
  - **Model & Research Evaluation**: Confusion matrix, per-class metrics, false alert rates, attack-onset delay, throughput.
  - **Reports & Settings**: Export tools (JSON/CSV), IP redaction toggle, and system configuration.
- [x] Frontend build verification (`npm run build` exits 0 with zero errors).

### Phase 9 — Dataset & Research Methodology
- [x] Document methodology in `docs/research_methodology.md`.
- [x] Add session-separated dataset adapters with cross-split contamination defense.
- [x] Evaluated demo model on held-out test sessions: 192 train windows, 192 validation windows, test results at 0%, 10%, 30% loss saved in `artifacts/demo/model.report.json`.

### Phase 10 — Verification, Security Review & Documentation
- [x] Comprehensive automated test suite: **36/36 tests passing** in `pytest`.
- [x] Documentation: `README.md`, `docs/demo_script.md`, `docs/security_and_privacy.md`, `docs/research_methodology.md`, `.env.example`.
- [x] Final verification report prepared.
