# NetGuard Evidence Resilience Engine (ERE) — Professor Demonstration Script (6–8 Minutes)

This script provides an interactive, structured walkthrough for demonstrating the **Evidence Resilience Engine (ERE)** to academic reviewers, professors, thesis committees, and security architects.

---

## Pre-Flight Checklist (Under 1 Minute)
1. Ensure the Python virtual environment is activated:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Verify local demo PCAPs and model artifacts exist:
   ```powershell
   .\.venv\Scripts\python.exe -m backend.ml generate-demo-data
   ```
3. Run the automated test suite (77 passed, 2 skipped, 0 failed):
   ```powershell
   .\.venv\Scripts\python.exe -m pytest -v
   ```
4. Start the NetGuard application server:
   ```powershell
   .\.venv\Scripts\python.exe -m backend.main --server --port 8000
   ```
5. Open your browser to `http://localhost:8000`.

---

## Step 1: Observatory Baseline & Capture Quality Context (1 Minute)
- **Visual Aesthetic:** Note the high-contrast analytical console with clean typography and semantic status badges.
- **Academic Honesty:** Point to the top header badge (`DEMO / SYNTHETIC`).
  - *Talking Point:* *"NetGuard never masquerades synthetic demo traffic as live physical captures. All demo data is generated locally and deterministically with tagged scopes."*
- **Capture Quality Indicator:** Point to the observation health card.
  - *Talking Point:* *"Crucially, when OS counters or kernel interfaces are absent, NetGuard reports them explicitly as `UNAVAILABLE` or `UNKNOWN` rather than faking '0% packet loss'."*
- **Threat Alerts:** Navigate to **Alerts & Evidence**, click on an incident (`SYN_FLOOD`), and inspect the **Evidence Passport**: explainable rule triggers, uncalibrated detector score, and capture quality context.
  - *Talking Point:* *"The Evidence Passport establishes what is and is not supported by observed evidence before any perturbation is run."*

---

## Step 2: Evidence Resilience Studio — Single Replay Baseline (1.5 Minutes)
- Navigate to **Replay Lab** in the navigation bar.
- Note the four dedicated sub-navigation workflows:
  `[ Single Replay | Robustness Atlas | Next Observation | Evidence Lineage ]`
- In **Single Replay**:
  - Select source capture: `test-SYN_FLOOD-0.pcap`.
  - Notice the prominent advisory banner: `OFFLINE SIMULATION — NO PACKETS TRANSMITTED`.
  - Configure a single perturbation: `Loss Mode: Random`, `Drop Rate: 15%`, `Seed: 42`.
  - Click **Run Counterfactual Verification**.
  - Review baseline vs. perturbed window counts and the feature shift table.
  - *Talking Point:* *"Notice the Non-Mutation Guarantee: this counterfactual experiment appends child findings but never rewrites, downgrades, or deletes the original incident."*

---

## Step 3: Core Novelty A — The Observation Robustness Atlas (2 Minutes)
- Switch to the **Robustness Atlas** sub-tab.
- **The Sweep Builder:**
  - Explain the multi-scenario parameter matrix: Selectable scenario families (**Random Loss**, **Burst Loss**, **Directional Visibility Loss**), loss rates (**5%, 10%, 20%, 30%, 50%**), and reproducible seed ensemble (**11, 23, 37, 51, 79**).
  - Point to the run budget: `Max Run Budget: 30 runs`.
  - Click **Execute Sweep Matrix**.
- **Real-Time Execution & Accounting:**
  - Observe the live progress bar: e.g., *"Scenario 12 of 25 (48%)... Executing random_rate20_seed37"*.
  - *Talking Point:* *"Each run executes with fresh isolated detector state so anomaly baselines never leak across scenarios. Furthermore, windows are strictly aligned by `(source_ip, timestamp)` canonical keys rather than naive list positions."*
- **Atlas Visualizations:**
  - **Overall Stability Verdict:** Inspect the verdict card (`STABLE`, `SENSITIVE`, or `INCONCLUSIVE`).
  - *Talking Point:* *"NetGuard labels stability as 'Stable within tested parameter space'—never a universal zero-day defense guarantee."*
  - **Robustness Matrix (Heatmap Table):** Point to the `Profile × Nominal Rate` grid showing evaluated runs, mean realized omission rate, alert retention rate, and decision shifts.
  - **Catalog & Feature Drift:** Click on an individual scenario row to view exact packet counts (Source, Omitted, Retained) and feature deltas (`syn_rate`, `completed_fraction`, `bytes_per_second`).

---

## Step 4: Core Novelty B — Passive Next-Observation Planner (1.5 Minutes)
- Switch to the **Next Observation** sub-tab.
- Select the target incident from the Evidence Passport dropdown and correlate the completed robustness sweep.
- Point to the prominent banner: `PASSIVE ONLY — NO PACKETS TRANSMITTED`.
- **Ranked Explainable Recommendations:**
  - Review the numbered triage table:
    1. **`OBS-CAP-01` (High Priority):** *Audit Ingestion Queue Depth & Kernel Buffer Health* — Triggered because kernel drop counters were reported `UNAVAILABLE`.
    2. **`OBS-DIR-01` (High Priority):** *Verify Bidirectional SPAN / Tap Placement* — Triggered because directional perturbation flipped detection, indicating reverse-path blind spots.
    3. **`OBS-SWEEP-01` (High Priority):** *Run High-Density Seed Sweep in Replay Lab* — Triggered by instability observed at low omission rates.
  - Point to the evidence trace grid for each item:
    - *Triggering Evidence Gap*
    - *Justifying Robustness Scenario*
    - *Recommended Passive Action*
    - *Expected Clarification*
    - *Effort & Privacy Impact*
  - *Talking Point:* *"Every recommendation is generated by deterministic, auditable rules citing real recorded fields. Notice that every action is strictly passive: zero active network probes, port scans, or firewall resets are ever recommended."*

---

## Step 5: Core Novelty C — Tamper-Evident Evidence Lineage (1.5 Minutes)
- Switch to the **Evidence Lineage** sub-tab.
- **Cryptographic Hash Chain:**
  - Click **Recompute & Verify Chain**.
  - Point to the green verification badge: `CHAIN VERIFICATION: VALID (8+ Verified Blocks)`.
  - *Talking Point:* *"Every incident, sweep configuration, and planner report is stored as an RFC 8785 canonical JSON manifest with a SHA-256 digest bound into an append-only SQLite hash chain with genesis block linkage."*
- **Manifest Inspector:**
  - Click an event block (e.g., `#8 ROBUSTNESS_SWEEP_COMPLETED`).
  - Inspect the canonical manifest payload, previous block hash, and recomputed event hash.
  - Click the **Copy** icon next to the manifest digest.
- **Export Reproducible Evidence Bundle:**
  - Click **Export Evidence Bundle**.
  - Inspect the downloaded JSON file: it links the Evidence Passport reference, robustness sweep summary, passive observation plan, and verified lineage status into a single auditable artifact.
- **Honest Threat Boundary:**
  - Highlight the threat boundary notice:
  - *Talking Point:* *"We explicitly disclose that local hash chains prove tamper evidence within application storage; they do not constitute digital signatures or protection against root disk overwrites."*

---

## Step 6: Summary & Academic Defense (30 Seconds)
- Summarize the unified research contribution:
  *"NetGuard closes the observation-incompleteness gap by demonstrating that threat alerts can be systematically stress-tested against controlled observation failures, paired with actionable passive follow-up guidance, and cryptographically verified through reproducible evidence lineage."*
- Invite questions from the committee.
