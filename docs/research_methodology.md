# NetGuard Evidence Resilience Engine (ERE) — Research Methodology & Evaluation Framework

## 1. Executive Summary & Research Question

Network intrusion detection systems (NIDS) are overwhelmingly evaluated under an artificial assumption of **lossless, perfect packet capture**. In real-world enterprise deployments, network monitors routinely suffer from driver ring-buffer drops, kernel queue overflows, late/out-of-order packets, asymmetric routing, and CPU throttling.

Recent surveys confirm this critical blind spot: *A survey on network traffic analysis with incomplete data* (Computer Communications, 2026) reports that among 55 recent studies on network traffic analysis, **only 10 explicitly considered the effect of data incompleteness**.

NetGuard operationalizes the following research question:
> **Core Research Question:** *For a fixed observed capture and fixed detector configuration, how does the incident decision vary across reproducible families and severities of observation impairment; which specific evidence gaps are associated with instability; and what additional passive observations should an analyst prioritize next? Can each result be independently reproduced from a manifest and verified evidence lineage?*

NetGuard does not claim that counterfactual reasoning, packet loss testing, or hash chains are unprecedented in isolation. Rather, NetGuard’s specific, defensible contribution is the **Evidence Resilience Engine (ERE)**: the unified integration of per-incident robustness to multi-dimensional observation failures, evidence-gap-driven passive triage planning, and tamper-evident cryptographic lineage in a streaming observatory.

---

## 2. Related-Work Positioning & Comparison Table

To maintain rigorous scientific honesty, NetGuard explicitly positions itself relative to recent foundational literature:

| Prior Approach / Source | What It Already Covers | What NetGuard Adds Operationally | Operational Limitations |
|---|---|---|---|
| **Survey on Network Traffic Analysis with Incomplete Data** (*Computer Communications*, 2026) | Establishes that packet loss severely degrades ML traffic classifiers; identifies research gap across 55 papers. | Implements a real-time, per-incident multi-scenario perturbation matrix (Random, Burst, Directional) directly in an operational network observatory. | Evaluates bounded parameter grids (rates $\le 50\%$, burst sizes $\le 8$); does not simulate arbitrary physical-layer signal jamming. |
| **CANDICE** (*Future Generation Computer Systems*, 2026) | Explores counterfactual explanations and feature perturbation for explainable NIDS. | Measures realization-level packet omission rather than arbitrary feature-space perturbation; enforces source PCAP and original incident non-mutation. | Advisory only; counterfactual simulation does not prove the true causal packet distribution of the live network. |
| **Forensic-Ready Intrusion Detection** (*MethodsX*, June 2026) | Demonstrates graph-based host modeling, explainable detection, and reproducible forensic artifacts. | Adds RFC 8785 canonical manifest serialization, append-only SQLite SHA-256 hash chains, and one-click evidence bundle export linking sweep to alert. | Tamper-evident within application bounds; does not protect against a hostile system administrator overwriting the host OS disk. |
| **Reliability Auditing of ML-IDS Explanations** (2026) | Proves that ML explanations often suffer from instability, explanation disagreement, and sensitivity to spurious features. | Directly couples measured decision-shift boundaries with a rule-based passive observation planner recommending concrete operator verification steps. | Recommendations are heuristic triage suggestions; they do not replace human analyst investigation or formal threat intelligence. |
| **PAVE Framework** (*IoT Network Security*, 2026) | Emphasizes protocol-validity-aware perturbation over synthetic feature vector jitter. | Perturbations are executed on raw packet streams through the canonical `parse_packet` and bounded flow engine, maintaining protocol validity across runs. | Simulation is constrained to metadata-level parsing; payloads are neither inspected nor altered. |

---

## 3. The Evidence Resilience Engine (ERE) Architecture

The ERE consists of three tightly coupled, mutually reinforcing components:

```
[ Observed Network Traffic ]
            │
            ▼
[ Incident Detection & Quality Telemetry ] ──► [ Evidence Passport Saved ] (Immutable)
            │                                             │
            ├─────────────────────────────────────────────┤
            ▼                                             ▼
[ Observation Robustness Atlas ]             [ Tamper-Evident Lineage ]
- Multi-scenario failure matrix              - Canonical RFC 8785 JSON
- Realized packet accounting                 - SHA-256 Block Hashing
- Isolated detector cloning                  - Genesis Block Linkage
- Canonical window alignment                 - Verifier: VALID / INVALID
            │                                             │
            └──────────────────────┬──────────────────────┘
                                   │
                                   ▼
                   [ Passive Next-Observation Planner ]
                   - Deterministic evidence-gap rules
                   - Zero active network probes (Passive only)
                   - Ranked follow-up triage recommendations
                                   │
                                   ▼
                   [ Reproducible Evidence Bundle ]
```

---

## 4. Component Deep-Dive

### 4.1 Pillar A: Observation Robustness Atlas

Rather than testing an arbitrary single loss rate and single random seed, the Atlas executes a bounded, reproducible matrix of observation-failure scenarios:

1. **Failure Dimensions**:
   - **Baseline:** Direct re-processing with zero simulated loss.
   - **Random Loss:** Pseudo-random packet omission across an explicit seed ensemble (e.g. 11, 23, 37, 51, 79) and rates (5%, 10%, 20%, 30%, 50%).
   - **Burst Loss:** Contiguous omission clusters simulating kernel buffer overflow, configured by burst size ($k$) and interval ($m$).
   - **Directional Visibility Loss:** Asymmetric visibility omission conditioned on source/destination endpoints, testing resilience to unidirectional tap placement or asymmetric routing.

2. **Accurate Packet Accounting**:
   The engine strictly distinguishes configured parameters from realized effects, recording:
   - $N_{\text{source}}$: Total packets eligible for the experiment.
   - $N_{\text{omitted}}$: Packets dropped by simulation.
   - $N_{\text{retained}}$: Packets retained and fed to parser.
   - $R_{\text{realized}} = N_{\text{omitted}} / N_{\text{source}}$: Realized omission fraction.

3. **Canonical Window Alignment**:
   Baseline and perturbed windows are aligned using explicit `(source_ip, timestamp)` keys, rejecting naive `zip()` list pairing. The engine reports matched windows, baseline-only windows, perturbed-only windows, and window coverage percentage.

4. **Detector State Isolation**:
   To prevent anomaly baseline contamination across runs, each scenario clones a fresh, isolated `AnomalyDetector` while reusing the frozen fitted model artifact.

5. **Stability Verdict Semantics**:
   - `STABLE`: No decision shifts or alert drops observed across all eligible executed scenarios. Strictly labeled "Stable within tested parameter space".
   - `SENSITIVE`: One or more scenarios flip classification or decision. The exact lowest tested boundary (`lowest_boundary`) is identified.
   - `INCONCLUSIVE`: Insufficient baseline threat windows or low window coverage to establish a bounded verdict.

### 4.2 Pillar B: Passive Next-Observation Planner

The planner is a deterministic, explainable rule engine converting evidence gaps into prioritized operator checks:

- **Mandatory Invariant:** `active_network_action: false`. The system never sends packets, port probes, injection frames, or automatic firewall blocks.
- **Traceability:** Every recommendation cites the specific rule ID (`OBS-CAP-01`, `OBS-DIR-01`, `OBS-SWEEP-01`, `OBS-RES-01`, `OBS-TIME-01`, `OBS-SYN-01`, `OBS-CORR-01`) and the exact triggering telemetry fields.
- **Disclosures:** Each action item details prerequisites, operational effort (`LOW`, `MEDIUM`, `HIGH`), and privacy implications (`NONE`, `LOW`, `MEDIUM`).

### 4.3 Pillar C: Tamper-Evident Evidence Lineage

Maintains a cryptographic chain of custody for all analytical events:

- **RFC 8785 Canonical JSON Serialization:** Enforces sorted dictionary keys and compact separators (`separators=(',', ':')`) for deterministic SHA-256 digest computation.
- **Continuous Hash Chain:** Persisted in an append-only SQLite table (`lineage_events`). Each block hash is computed as:
  $$H_i = \text{SHA-256}\left(\text{seq}_i \,\|\, \text{event\_id}_i \,\|\, \text{event\_type}_i \,\|\, \text{manifest\_digest}_i \,\|\, H_{i-1}\right)$$
  where Genesis block $H_0 = 0^{64}$.
- **Chain Verifier:** Independently recomputes all hashes from genesis to head, returning `VALID`, `INVALID` (identifying the first failing sequence ID), or `EMPTY`.
- **Reproducible Evidence Bundle:** An exportable JSON package uniting the Evidence Passport snapshot, sweep matrix, planner recommendations, and lineage verification status.

---

## 5. Security & Threat Boundary Disclosures

1. **Passive Observation Only:** NetGuard is read-only and passive. It transmits zero network packets.
2. **Local Tamper Evidence:** SHA-256 hash chains detect accidental or unauthorized row modifications within the local database. They do not constitute asymmetric cryptographic digital signatures or protection against hostile administrators with root filesystem access.
3. **Synthetic Replay Bounds:** Perturbations evaluate detector sensitivity under modeled packet omission. They do not guarantee performance against physical jamming or unseen zero-day attacks.
4. **Metadata Privacy:** Evidence Passports, lineage manifests, and exported bundles contain behavioral network metadata only. Raw payload bytes are discarded during packet ingestion.
