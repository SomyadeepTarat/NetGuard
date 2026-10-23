# NetGuard Research Methodology & Evaluation Framework

## 1. Research Question & Objective

Network intrusion detection systems (NIDS) are routinely evaluated under the implicit assumption of **lossless, perfect packet capture**. In real-world enterprise deployments, network monitors suffer from driver ring-buffer drops, kernel-to-user-space queue overflows, out-of-order delivery, asymmetric routing, and CPU throttling.

NetGuard addresses the following core research question:
> **Research Question:** *How sensitive are network threat classifications and rule-based heuristic detections to observation-level packet loss, and can counterfactual offline replay provide actionable evidence-quality verification without rewriting or suppressing original alert records?*

Rather than claiming global novelty or guaranteed zero-day defense, NetGuard introduces **Capture-Aware Incident Verification**: an advisory pipeline that pairs suspicious-traffic alerts with inspectable evidence, measures capture telemetry quality, and subjects the underlying capture to controlled, deterministic perturbation profiles (random loss, burst loss, directional loss) to evaluate decision stability.

---

## 2. Experimental Design & Data Provenance

### 2.1 Dataset Layers

1. **Deterministic Local Synthetic PCAPs (`artifacts/demo/`):**
   - Generated entirely offline via Scapy packet construction without network transmission.
   - Fixed random seeds ensure 100% reproducible frame sequencing, IP addresses, port distributions, and payload lengths.
   - Used for unit testing, continuous integration, and professor demonstrations without external dependencies or privileged network adapters.
   - Visibly tagged with scope: `synthetic-demo`.

2. **External Benchmark Adapter (CIC-IDS2017 / Custom Captures):**
   - Structured JSON manifest mapping capture sessions to target splits (`train`, `validation`, `test`) and classes.
   - Supports evaluating held-out sessions from public benchmarks without requiring multi-gigabyte downloads for basic operation.
   - Manual placement instructions ensure compliance with data governance and licensing terms.

---

## 3. Strict Methodological Safeguards

To prevent subtle methodological flaws common in NIDS literature, NetGuard implements the following safeguards:

### 3.1 Session-Separated Splitting
- **Zero Cross-Split Contamination:** Dataset manifests enforce that each session/capture file exists in **exactly one split** (`train`, `validation`, or `test`).
- **No Temporal / Rolling-Window Leakage:** Models are never evaluated on overlapping time windows extracted from training captures.
- **No Device / IP Identity Overfitting:** The feature extractor operates on statistical behavioral aggregates (packet rates, byte rates, SYN/FIN ratios, port entropy) rather than memorizing specific IP addresses or MAC headers.

### 3.2 Uncalibrated Score Disclosure
- Random Forest output values are explicitly treated as **uncalibrated scores**, not true posterior probabilities of malicious intent.
- Decision thresholds are selected exclusively on the `validation` split to maximize attack F1 while strictly penalizing false positives on benign sessions.

### 3.3 Anomaly Detector Baseline Integrity
- The Isolation Forest anomaly detector requires a minimum warm-up window threshold (default: 20 windows) before reporting anomaly scores.
- During suspected threat intervals or degraded capture periods, baseline profile updating is **frozen** to prevent adversarial baseline poisoning.

---

## 4. Evaluation Metrics & Formulation

NetGuard reports empirical, measured performance metrics across the following dimensions:

| Metric | Definition & Purpose |
|---|---|
| **Per-Class Precision, Recall, F1** | Evaluates per-attack classification capability on held-out test sessions. |
| **Macro-F1 Score** | Balanced unweighted average across all classes (`BENIGN`, `PORT_SCAN`, `SYN_FLOOD`, `TRAFFIC_FLOOD`). |
| **Confusion Matrix** | Full contingency matrix showing misclassifications between specific attack families and benign traffic. |
| **False Alerts per Benign Hour** | Normalized rate of false alarms per hour of active benign observation: $\text{FAPh} = \frac{\text{False Alerts} \times 3600}{\text{Benign Observation Seconds}}$. Alerts are suppressed within a 10s cooldown per source/class to reflect realistic SOC operational impact. |
| **Attack-Onset Detection Delay** | Measured in elapsed seconds from capture onset to the first true positive alert on held-out attack sessions. |
| **Throughput (windows/sec)** | End-to-end processing throughput for feature extraction, baseline heuristics, and model inference. |

---

## 5. Counterfactual Perturbation Profiles

The signature feature of the NetGuard Replay Lab is offline re-processing of an identical capture through the canonical parser, flow engine, and ML pipeline under controlled perturbation:

1. **Random Packet Loss:** Independent Bernoulli trials where each packet is omitted with probability $p \in [0.05, 0.50]$ under a deterministic RNG seed.
2. **Burst Packet Loss:** Clustered packet omission simulating kernel buffer overflows, dropping contiguous runs of $k$ packets every $m$ packets.
3. **Directional Loss:** Asymmetric visibility omission dropping traffic in either forward or reverse direction, simulating asymmetric routing or tap failure.

### Stability Verdicts
- **STABLE:** The classification and threat confidence remain resilient under the chosen perturbation rate.
- **SENSITIVE:** The decision flips (e.g., from `SYN_FLOOD` to `BENIGN` or `UNCERTAIN`), indicating that the original finding relies on fragile handshake evidence. Corroborating telemetry is recommended.
- **INCONCLUSIVE:** The input session contained no threat windows under baseline conditions.

### The Non-Mutation Guarantee
Counterfactual perturbation is **strictly advisory**. A sensitivity verdict never modifies, deletes, suppresses, or downgrades the original alert record in the SQLite Evidence Passport repository.
