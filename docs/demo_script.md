# NetGuard Professor Demonstration Script (5–8 Minutes)

This script provides an interactive, structured walkthrough for demonstrating NetGuard to academic reviewers, professors, or evaluation committees.

---

## Pre-Flight Checklist (Under 1 Minute)
1. Ensure the Python virtual environment is activated.
2. Launch the NetGuard backend server:
   ```bash
   .venv\Scripts\python.exe -m backend.main --server
   ```
3. Open your browser to `http://localhost:8000` (or `http://localhost:5173` if running `npm run dev`).
4. Notice that **no live network adapter, administrative privileges, or external cloud API keys are required**. The system launches automatically into deterministic demo mode.

---

## Step 1: Dashboard Overview & Academic Honesty (1 Minute)
- **Visual Aesthetic:** Point out the dark slate/cyan analyst console design.
- **Demo Mode Banner:** Highlight the visible `DEMO / SYNTHETIC` badge in the header.
  - *Talking Point:* *"NetGuard never masquerades synthetic or simulated traffic as live network capture. Everything displayed here is generated locally and deterministically."*
- **Key Cards:** Review Packets/sec, Bytes/sec, Active Hosts, Active Flows, and Protocol Breakdown (TCP, UDP, ICMP, ARP, DNS).
- **Capture Quality Panel:** Point to the observation health card.
  - *Talking Point:* *"Notice the status is `DEGRADED` or `HEALTHY` with clear attribution. Crucially, missing counters are reported as `UNAVAILABLE` or `UNKNOWN`—never faked as '0% packet loss'."*

---

## Step 2: Flow Engine & Host Communication Graph (1 Minute)
- Click on **Flows & Traffic** in the navigation bar.
- Point out the bidirectional 5-tuple tracking, directional byte ratios, and observed TCP flag combinations (`SYN, ACK`, `FIN`).
- Switch to the **Host Explorer** view:
  - Explain the interactive host-to-host communication graph.
  - *Talking Point:* *"We clearly disclose that this is an observed communication relationship graph, not a physical network topology diagram. We do not infer unobserved routers or switches."*
  - Click on a host node to inspect its active sessions and associated threat alerts.

---

## Step 3: Alerts & The Evidence Passport (1.5 Minutes)
- Navigate to **Threat Alerts**.
- Select an active incident (e.g., `SYN_FLOOD` or `PORT_SCAN`).
- Expand the **Evidence Passport**:
  - Show the **Three-Pillar Analysis**:
    1. **Explainable Rules:** Transparent thresholds (e.g., `SYN Rate > 50 pkts/s`, `SYN/ACK Ratio > 10.0`).
    2. **Known-Pattern Classifier:** Random Forest score with an explicit notice that scores are uncalibrated and not attack probabilities.
    3. **Anomaly Detector:** Isolation Forest anomaly indicator with baseline warm-up readiness state.
  - **Capture Quality Context:** Explains whether observation telemetry was degraded when the alert was triggered.
  - **Actionable Investigation Steps:** Recommended non-destructive investigation commands (e.g., checking host netstat, inspecting connection states) without automated active blocking.

---

## Step 4: Capture-Aware Incident Verification / Replay Lab (2 Minutes)
*This is the signature research contribution of the project.*
- Navigate to **Replay Lab**.
- Notice the prominent header warning: `OFFLINE SIMULATION — NO PACKETS TRANSMITTED`.
- Select an offline capture from the dropdown (e.g., `test-SYN_FLOOD-0.pcap`).
- Configure a counterfactual scenario:
  - Injected Omission Rate: `15%`
  - Loss Profile: `Random Packet Loss` (or `Burst Packet Loss`)
  - Seed: `42` (deterministic reproducibility)
- Click **Run Counterfactual Verification**.
- Review the comparative results:
  - **Baseline (0% Loss) vs Perturbed (15% Loss)** threat window counts.
  - **Stability Verdict:** `STABLE` (or `SENSITIVE`).
  - **Feature Shift Table:** Inspect how raw features (e.g., `syn_count`, `packet_rate`) shifted under the simulated loss.
- **The Non-Mutation Principle:**
  - *Talking Point:* *"Observe that running this counterfactual experiment does not rewrite, delete, or downgrade the original alert. Replay sensitivity is advisory evidence presented alongside the incident for the analyst."*

---

## Step 5: Research Model Evaluation (1 Minute)
- Navigate to **Model Evaluation**.
- Show the held-out test evaluation report:
  - Per-class Precision, Recall, and F1 scores.
  - Macro-F1 across all 4 classes.
  - Full Confusion Matrix.
  - Operational metrics: False Alerts per Benign Hour and Attack-Onset Detection Delay.
  - *Talking Point:* *"If a model hasn't been evaluated, the UI displays 'Not evaluated yet'—we never manufacture synthetic benchmark numbers."*

---

## Step 6: Reports, IP Redaction & Wrap-Up (30 Seconds)
- Navigate to **Settings & Reports**.
- Toggle **Pseudonymize IP Addresses**.
- Click **Download JSON** or **Download CSV** to demonstrate sanitized Evidence Passport export for compliance and SIEM ingestion.
- Summarize: *"NetGuard delivers an advisory, defensible, evidence-aware threat observatory that remains honest about capture limitations and provides verifiable research tools."*
