"""Passive Next-Observation Planner.

Converts observed evidence gaps, capture quality limitations, and robustness sensitivity results
into a ranked, explainable list of additional passive observations or checks that reduce
investigative uncertainty.

Critical Guarantees:
1. Passive only: Never recommends active probing, packet injection, port scanning, or firewall changes.
2. Deterministic & Transparent: Evaluates explicit evidence-gap rules; no hallucinated narratives.
3. Traceable: Every recommendation cites the exact recorded telemetry field, scenario, or rule ID.
4. Privacy-aware: Discloses effort, prerequisites, and privacy implications.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class PassiveRecommendation:
    recommendation_id: str
    title: str
    priority: str  # HIGH, MEDIUM, LOW
    score: int     # 0-100 for deterministic ranking
    trigger_evidence: str
    justifying_scenario: Optional[str]
    what_to_observe_next: str
    expected_clarification: str
    prerequisites: str
    expected_effort: str  # LOW, MEDIUM, HIGH
    privacy_impact: str    # NONE, LOW, MEDIUM
    rule_id: str
    active_network_action: bool = False  # Mandatory invariant: MUST be False

    def to_dict(self) -> dict:
        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "priority": self.priority,
            "score": self.score,
            "trigger_evidence": self.trigger_evidence,
            "justifying_scenario": self.justifying_scenario,
            "what_to_observe_next": self.what_to_observe_next,
            "expected_clarification": self.expected_clarification,
            "prerequisites": self.prerequisites,
            "expected_effort": self.expected_effort,
            "privacy_impact": self.privacy_impact,
            "rule_id": self.rule_id,
            "active_network_action": False,
        }


@dataclass
class ObservationPlan:
    plan_id: str
    target_alert_id: Optional[str] = None
    target_sweep_id: Optional[str] = None
    plan_mode: str = "INCIDENT_LINKED"  # "INCIDENT_LINKED" or "SWEEP_ONLY_ADVISORY"
    status: str = "READY"  # READY, INSUFFICIENT_EVIDENCE, NO_GAPS_IDENTIFIED
    insufficient_reason: Optional[str] = None
    total_recommendations: int = 0
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    active_network_action: bool = False
    disclaimer: str = (
        "PASSIVE OBSERVATIONS ONLY — NO PACKETS TRANSMITTED. Recommendations guide analyst review "
        "of existing capture handles, tap placements, and counterfactual replay parameters. "
        "NetGuard never performs active network probes, port scans, or automated host blocking."
    )

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "target_alert_id": self.target_alert_id,
            "target_sweep_id": self.target_sweep_id,
            "plan_mode": self.plan_mode,
            "status": self.status,
            "insufficient_reason": self.insufficient_reason,
            "total_recommendations": self.total_recommendations,
            "recommendations": self.recommendations,
            "evidence_summary": self.evidence_summary,
            "active_network_action": False,
            "disclaimer": self.disclaimer,
        }


class PassiveNextObservationPlanner:
    """Deterministic, explainable rule-based planner for next passive observations."""

    def generate_plan(
        self,
        passport: Optional[Dict[str, Any]] = None,
        sweep_run: Optional[Dict[str, Any]] = None,
        flow_context: Optional[Dict[str, Any]] = None,
    ) -> ObservationPlan:
        """Evaluates evidence gaps and generates ranked passive follow-up observations."""
        if not passport and not sweep_run and not flow_context:
            return ObservationPlan(
                plan_id=f"plan-{uuid.uuid4().hex[:10]}",
                target_alert_id=None,
                target_sweep_id=None,
                plan_mode="SWEEP_ONLY_ADVISORY",
                status="INSUFFICIENT_EVIDENCE",
                insufficient_reason="Neither Evidence Passport nor Robustness Sweep data was supplied.",
                total_recommendations=0,
                recommendations=[],
                evidence_summary={"error": "Neither Evidence Passport nor Robustness Sweep data was supplied."},
                disclaimer=(
                    "SWEEP-ONLY ADVISORY PLAN — NO EVIDENCE PASSPORT LINKED. "
                    "Recommendations are derived strictly from counterfactual robustness sweep instability. "
                    "No confirmed threat incident or live capture-quality passport is associated with this plan."
                ),
            )

        # ---------------------------------------------------------------------
        # MODE B: Sweep-Only Advisory Planning (No Evidence Passport)
        # ---------------------------------------------------------------------
        if passport is None and sweep_run is not None:
            sweep_id = sweep_run.get("run_id")
            plan_mode = "SWEEP_ONLY_ADVISORY"
            disclaimer = (
                "SWEEP-ONLY ADVISORY PLAN — NO EVIDENCE PASSPORT LINKED. "
                "Recommendations are derived strictly from counterfactual robustness sweep instability. "
                "No confirmed threat incident or live capture-quality passport is associated with this sweep."
            )
            envelope = sweep_run.get("envelope") or {}
            scenario_results = sweep_run.get("scenario_results", [])
            stability = sweep_run.get("stability_verdict", "PENDING")
            lowest_boundary = envelope.get("lowest_tested_boundary")
            baseline_threat_windows = envelope.get("baseline_threat_windows", 0)

            sweep_status = sweep_run.get("status") or ("completed" if (envelope or scenario_results or stability != "PENDING") else "unknown")
            completed_scenarios = sweep_run.get("completed_scenarios")
            if completed_scenarios is None:
                completed_scenarios = len(scenario_results) if scenario_results else (1 if lowest_boundary else 0)

            if sweep_status in ("failed", "cancelled", "running", "queued") or sweep_status not in ("completed", "unknown"):
                return ObservationPlan(
                    plan_id=f"plan-{uuid.uuid4().hex[:10]}",
                    target_alert_id=None,
                    target_sweep_id=sweep_id,
                    plan_mode=plan_mode,
                    status="INSUFFICIENT_EVIDENCE",
                    insufficient_reason=(
                        f"Selected robustness sweep '{sweep_id}' is in state '{sweep_status}'. "
                        "Only completed sweeps can be used for advisory planning."
                    ),
                    total_recommendations=0,
                    recommendations=[],
                    evidence_summary={"sweep_status": sweep_status, "completed_scenarios": completed_scenarios},
                    disclaimer=disclaimer,
                )

            if completed_scenarios == 0 and not lowest_boundary and not scenario_results:
                return ObservationPlan(
                    plan_id=f"plan-{uuid.uuid4().hex[:10]}",
                    target_alert_id=None,
                    target_sweep_id=sweep_id,
                    plan_mode=plan_mode,
                    status="INSUFFICIENT_EVIDENCE",
                    insufficient_reason=f"Selected robustness sweep '{sweep_id}' contains 0 completed scenarios.",
                    total_recommendations=0,
                    recommendations=[],
                    evidence_summary={"sweep_status": sweep_status, "completed_scenarios": 0},
                    disclaimer=disclaimer,
                )

            recommendations: List[PassiveRecommendation] = []

            # 1. Low boundary / SENSITIVE instability
            if lowest_boundary or stability == "SENSITIVE":
                rec_scenario = lowest_boundary.get("scenario_id") if lowest_boundary else "SENSITIVE_SWEEP"
                drop_pct = int(lowest_boundary['nominal_drop_rate'] * 100) if lowest_boundary else 20
                shifts = lowest_boundary.get("decision_shifts", 1) if lowest_boundary else 1
                seed = lowest_boundary.get("seed", 42) if lowest_boundary else 42
                loss_mode = lowest_boundary.get("loss_mode", "random") if lowest_boundary else "random"
                recommendations.append(
                    PassiveRecommendation(
                        recommendation_id="OBS-SWEEP-01",
                        title="Run High-Density Seed Sweep in Replay Lab at Low Omission Rates",
                        priority="HIGH",
                        score=85,
                        trigger_evidence=(
                            f"Decision flipped under controlled {loss_mode} packet loss "
                            f"(Boundary: {drop_pct}% in scenario {rec_scenario}, seed {seed}, {shifts} decision shift(s))"
                        ),
                        justifying_scenario=rec_scenario,
                        what_to_observe_next=(
                            "Execute a fine-grained perturbation sweep in Replay Lab between 1% and 10% packet loss with at least "
                            "10 random seeds to establish the exact fragility curve."
                        ),
                        expected_clarification=(
                            "Reveals whether the incident alert is hypersensitive to minimal packet omissions or stable across other seeds."
                        ),
                        prerequisites="Offline Replay Lab access.",
                        expected_effort="LOW",
                        privacy_impact="NONE",
                        rule_id="OBS-SWEEP-01",
                        active_network_action=False,
                    )
                )

            # 2. Directional loss vulnerability
            dir_flips = [
                r for r in scenario_results
                if r.get("loss_mode") == "directional" and r.get("decision_shifts", 0) > 0
            ]
            if dir_flips:
                sc_id = dir_flips[0].get("scenario_id")
                shifts = sum(r.get("decision_shifts", 0) for r in dir_flips)
                recommendations.append(
                    PassiveRecommendation(
                        recommendation_id="OBS-DIR-01",
                        title="Verify Bidirectional SPAN / Tap Placement at Authorized Observation Point",
                        priority="HIGH",
                        score=90,
                        trigger_evidence=(
                            f"Directional loss sensitivity triggered {shifts} decision shift(s) across {len(dir_flips)} scenario(s) (first: {sc_id})"
                        ),
                        justifying_scenario=sc_id,
                        what_to_observe_next=(
                            "Confirm that the passive network tap or switch mirror port is configured to mirror both transmit (Tx) "
                            "and receive (Rx) traffic. Asymmetric routing can prevent the sensor from observing SYN-ACK and ACK replies."
                        ),
                        expected_clarification=(
                            "Distinguishes an asymmetric observation gap (sensor blind spot) from a genuine unacknowledged attack flood."
                        ),
                        prerequisites="Authorized network tap/mirror configuration review with network engineering team.",
                        expected_effort="MEDIUM",
                        privacy_impact="LOW",
                        rule_id="OBS-DIR-01",
                        active_network_action=False,
                    )
                )

            # 3. Burst loss sensitivity
            burst_flips = [
                r for r in scenario_results
                if r.get("loss_mode") == "burst" and r.get("decision_shifts", 0) > 0
            ]
            if burst_flips:
                sc_id = burst_flips[0].get("scenario_id")
                shifts = sum(r.get("decision_shifts", 0) for r in burst_flips)
                recommendations.append(
                    PassiveRecommendation(
                        recommendation_id="OBS-BURST-01",
                        title="Audit Ingestion Queue Burst Tolerance & Microburst Drops",
                        priority="MEDIUM",
                        score=75,
                        trigger_evidence=(
                            f"Burst loss sensitivity triggered {shifts} decision shift(s) across {len(burst_flips)} scenario(s) (first: {sc_id})"
                        ),
                        justifying_scenario=sc_id,
                        what_to_observe_next=(
                            "Review switch and host network interface buffer queue lengths for microburst drops during high traffic intervals."
                        ),
                        expected_clarification=(
                            "Confirms whether short burst omissions degrade detection confidence."
                        ),
                        prerequisites="Switch/router queue telemetry or interface drop statistics.",
                        expected_effort="LOW",
                        privacy_impact="NONE",
                        rule_id="OBS-BURST-01",
                        active_network_action=False,
                    )
                )

            sorted_recs = sorted(recommendations, key=lambda r: (-r.score, r.recommendation_id))
            status = "READY" if sorted_recs else "NO_GAPS_IDENTIFIED"
            evidence_summary = {
                "sweep_id": sweep_id,
                "completed_scenarios": completed_scenarios,
                "sweep_stability": stability,
                "lowest_boundary": lowest_boundary,
                "direction_flips_count": len(dir_flips),
                "burst_flips_count": len(burst_flips),
                "baseline_threat_windows": baseline_threat_windows,
                "is_incident_linked": False,
            }

            return ObservationPlan(
                plan_id=f"plan-{uuid.uuid4().hex[:10]}",
                target_alert_id=None,
                target_sweep_id=sweep_id,
                plan_mode=plan_mode,
                status=status,
                insufficient_reason=None,
                total_recommendations=len(sorted_recs),
                recommendations=[r.to_dict() for r in sorted_recs],
                evidence_summary=evidence_summary,
                active_network_action=False,
                disclaimer=disclaimer,
            )

        # ---------------------------------------------------------------------
        # MODE A: Incident-Linked Planning (Evidence Passport Available)
        # ---------------------------------------------------------------------

        alert_id = passport.get("alert_id") if passport else None
        recommendations: List[PassiveRecommendation] = []

        # Extract Evidence Dimensions
        quality = (passport.get("capture_quality") or {}) if passport else {}
        indicators = {ind.get("name", ""): ind.get("value") for ind in quality.get("indicators", [])}
        queue_drops = indicators.get("Queue Drops", 0) or 0
        state_evictions = indicators.get("State Evictions", 0) or 0
        late_packets = indicators.get("Late Packets", 0) or 0
        kernel_status = quality.get("overall_status", "UNKNOWN")

        handshake = (passport.get("fragility") or {}) if passport else {}
        evidence = (passport.get("evidence") or {}) if passport else {}
        decision = passport.get("decision", "UNKNOWN") if passport else "UNKNOWN"
        detector_class = passport.get("detector_class", "UNKNOWN") if passport else "UNKNOWN"

        # Sweep-specific telemetry
        envelope = (sweep_run.get("envelope") or {}) if sweep_run else {}
        stability = sweep_run.get("stability_verdict", "PENDING") if sweep_run else "UNTESTED"
        lowest_boundary = envelope.get("lowest_tested_boundary") if envelope else None
        scenario_results = sweep_run.get("scenario_results", []) if sweep_run else []

        # -------------------------------------------------------------------------
        # RULE 1: Queue Drops or Hardware Capture Saturation (High Priority)
        # -------------------------------------------------------------------------
        kernel_ind = next(
            (ind for ind in quality.get("indicators", []) if "kernel" in ind.get("name", "").lower()),
            None
        )
        kernel_unavailable = kernel_ind is not None and kernel_ind.get("status") in ("UNAVAILABLE", "UNKNOWN")

        if queue_drops > 0 or kernel_unavailable:
            trigger_text = (
                f"Kernel packet drop counters are unavailable ({kernel_ind.get('status')})"
                if kernel_unavailable and queue_drops == 0
                else f"Queue drops recorded ({queue_drops} dropped packets during observation window)"
            )
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-CAP-01",
                    title="Audit Ingestion Queue Depth & Kernel Ring Buffer Health",
                    priority="HIGH",
                    score=95,
                    trigger_evidence=trigger_text,
                    justifying_scenario=None,
                    what_to_observe_next=(
                        "Inspect NetGuard worker thread saturation, operating system buffer sizes, and interface ring buffer counters. "
                        "Determine if packet drops coincided with high-volume bursts."
                    ),
                    expected_clarification=(
                        "Confirms whether incomplete flows were caused by host capture-queue saturation rather than true network omissions."
                    ),
                    prerequisites="Local host OS diagnostic access (e.g. ethtool, netstat, or Task Manager).",
                    expected_effort="LOW",
                    privacy_impact="NONE",
                    rule_id="OBS-CAP-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 2: Directional Asymmetry / Missing Reverse Visibility (High/Medium Priority)
        # -------------------------------------------------------------------------
        dir_flips = [
            r for r in scenario_results
            if r.get("loss_mode") == "directional" and r.get("decision_shifts", 0) > 0
        ]
        response_fraction = evidence.get("response_fraction", 1.0)
        completed_fraction = evidence.get("completed_fraction", 1.0)

        if dir_flips or response_fraction < 0.05 or (detector_class == "SYN_FLOOD" and completed_fraction < 0.1):
            sc_id = dir_flips[0].get("scenario_id") if dir_flips else None
            score = 90 if dir_flips else 75
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-DIR-01",
                    title="Verify Bidirectional SPAN / Tap Placement at Authorized Observation Point",
                    priority="HIGH" if dir_flips else "MEDIUM",
                    score=score,
                    trigger_evidence=(
                        f"Directional loss sensitivity triggered decision shifts ({len(dir_flips)} scenarios)"
                        if dir_flips
                        else f"Negligible reverse packet ratio ({response_fraction:.2f}) observed for endpoint"
                    ),
                    justifying_scenario=sc_id,
                    what_to_observe_next=(
                        "Confirm that the passive network tap or switch mirror port is configured to mirror both transmit (Tx) "
                        "and receive (Rx) traffic. Asymmetric routing can prevent the sensor from observing SYN-ACK and ACK replies."
                    ),
                    expected_clarification=(
                        "Distinguishes an asymmetric observation gap (sensor blind spot) from a genuine unacknowledged attack flood."
                    ),
                    prerequisites="Authorized network tap/mirror configuration review with network engineering team.",
                    expected_effort="MEDIUM",
                    privacy_impact="LOW",
                    rule_id="OBS-DIR-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 3: Low-Threshold Fragility Boundary (High Priority)
        # -------------------------------------------------------------------------
        if lowest_boundary or stability == "SENSITIVE":
            rec_scenario = lowest_boundary.get("scenario_id") if lowest_boundary else "SENSITIVE_SWEEP"
            drop_pct = int(lowest_boundary['nominal_drop_rate']*100) if lowest_boundary else 20
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-SWEEP-01",
                    title="Run High-Density Seed Sweep in Replay Lab at Low Omission Rates",
                    priority="HIGH",
                    score=85,
                    trigger_evidence=(
                        f"Decision flipped under controlled packet loss "
                        f"(Boundary: {drop_pct}% in scenario {rec_scenario})"
                    ),
                    justifying_scenario=rec_scenario,
                    what_to_observe_next=(
                        "Execute a fine-grained perturbation sweep in Replay Lab between 1% and 10% packet loss with at least "
                        "10 random seeds to establish the exact fragility curve."
                    ),
                    expected_clarification=(
                        "Reveals whether the incident alert is hypersensitive to minimal packet omissions or stable across other seeds."
                    ),
                    prerequisites="Offline Replay Lab access.",
                    expected_effort="LOW",
                    privacy_impact="NONE",
                    rule_id="OBS-SWEEP-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 4: State Cache Evictions (Medium Priority)
        # -------------------------------------------------------------------------
        if state_evictions > 0:
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-RES-01",
                    title="Review Active Flow Cache Sizing & Eviction Thresholds",
                    priority="MEDIUM",
                    score=70,
                    trigger_evidence=f"Active flow table state evictions observed ({state_evictions} evictions)",
                    justifying_scenario=None,
                    what_to_observe_next=(
                        "Inspect concurrent flow count and max_flows configuration in NetGuard. Determine if flow table capacity "
                        "was exceeded during high-cardinality scanning."
                    ),
                    expected_clarification=(
                        "Ensures flow state was not prematurely purged before TCP termination or completion could be witnessed."
                    ),
                    prerequisites="Sensor process configuration review.",
                    expected_effort="LOW",
                    privacy_impact="NONE",
                    rule_id="OBS-RES-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 5: Late or Out-of-Order Packets (Medium/Low Priority)
        # -------------------------------------------------------------------------
        if late_packets > 0:
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-TIME-01",
                    title="Audit Capture Timestamp Source & Reordering Tolerance",
                    priority="MEDIUM",
                    score=65,
                    trigger_evidence=f"Late or out-of-order packets arrived past rolling watermark ({late_packets} packets)",
                    justifying_scenario=None,
                    what_to_observe_next=(
                        "Check capture NIC hardware timestamping settings and system clock drift. Verify that multi-queue NICs "
                        "are not introducing packet reordering across cores."
                    ),
                    expected_clarification=(
                        "Eliminates rolling window boundary inaccuracies caused by packet arrival jitter."
                    ),
                    prerequisites="Interface driver and PTP/NTP synchronization verification.",
                    expected_effort="LOW",
                    privacy_impact="NONE",
                    rule_id="OBS-TIME-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 6: Fragile SYN Incompletion / Handshake Ambiguity (Medium Priority)
        # -------------------------------------------------------------------------
        if handshake.get("status") == "FRAGILE":
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-SYN-01",
                    title="Extend Passive Observation Window for Correlated TCP Handshake Completion",
                    priority="MEDIUM",
                    score=60,
                    trigger_evidence=(
                        f"Handshake fragility model reported finding can flip with "
                        f"{handshake.get('minimum_tested_pairs_to_change', 'few')} hypothetical completed pairs"
                    ),
                    justifying_scenario=None,
                    what_to_observe_next=(
                        "Review adjacent time-window metadata for the suspect source IP to check if subsequent SYN-ACK or ACK "
                        "packets arrived outside the immediate 5-second evaluation window."
                    ),
                    expected_clarification=(
                        "Confirms whether slow legitimate connections or high-latency handshakes were misclassified as SYN flood."
                    ),
                    prerequisites="Flow database inspection for adjacent time slices.",
                    expected_effort="LOW",
                    privacy_impact="LOW",
                    rule_id="OBS-SYN-01",
                )
            )

        # -------------------------------------------------------------------------
        # RULE 7: Adjacent Flow History & Port Cardinality Check (Low Priority)
        # -------------------------------------------------------------------------
        if decision == "UNCERTAIN" or quality.get("overall_status") == "DEGRADED":
            recommendations.append(
                PassiveRecommendation(
                    recommendation_id="OBS-CORR-01",
                    title="Correlate Secondary Passive Endpoints & DNS Query History",
                    priority="LOW",
                    score=40,
                    trigger_evidence="Finding classified as UNCERTAIN due to observation quality limitations",
                    justifying_scenario=None,
                    what_to_observe_next=(
                        "Cross-reference observed passive DNS queries and secondary flows associated with the suspect IP to confirm "
                        "whether activity matches automated software updates or scanning tools."
                    ),
                    expected_clarification=(
                        "Provides qualitative context from passive DNS without issuing any active DNS lookups or packet probes."
                    ),
                    prerequisites="Passive DNS cache and flow repository query.",
                    expected_effort="LOW",
                    privacy_impact="LOW",
                    rule_id="OBS-CORR-01",
                )
            )

        # Sort recommendations deterministically by score DESC, then recommendation_id ASC
        sorted_recs = sorted(recommendations, key=lambda r: (-r.score, r.recommendation_id))

        status = "READY" if sorted_recs else "NO_GAPS_IDENTIFIED"
        evidence_summary = {
            "queue_drops": queue_drops,
            "state_evictions": state_evictions,
            "late_packets": late_packets,
            "kernel_quality": kernel_status,
            "sweep_stability": stability,
            "lowest_boundary": lowest_boundary,
            "direction_flips_count": len(dir_flips),
            "is_incident_linked": True,
            "target_sweep_id": sweep_run.get("run_id") if sweep_run else None,
        }

        return ObservationPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:10]}",
            target_alert_id=alert_id,
            target_sweep_id=sweep_run.get("run_id") if sweep_run else None,
            plan_mode="INCIDENT_LINKED",
            status=status,
            insufficient_reason=None,
            total_recommendations=len(sorted_recs),
            recommendations=[r.to_dict() for r in sorted_recs],
            evidence_summary=evidence_summary,
        )
