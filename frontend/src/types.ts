export interface HealthResponse {
  status: string
  capture_running: boolean
  mode: string
  interface: string
  model_loaded: boolean
  model_scope: string
  uptime_seconds: float
  total_packets: number
  capture_quality_status: string
}

export type float = number

export interface QualityIndicator {
  name: string
  value: any
  status: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN' | 'UNAVAILABLE'
  availability: 'AVAILABLE' | 'UNAVAILABLE' | 'UNKNOWN'
  source: string
  description: string
  limitations: string
  last_updated: number
}

export interface CaptureQualityReport {
  overall_status: 'HEALTHY' | 'DEGRADED' | 'UNKNOWN' | 'UNAVAILABLE'
  overall_summary: string
  mode: string
  interface: string
  packets_received: number
  indicators: QualityIndicator[]
  timestamp: number
}

export interface OverviewData {
  status: 'CAPTURING' | 'STOPPED'
  mode: 'DEMO' | 'LIVE' | 'PCAP'
  interface: string
  uptime_seconds: number
  total_packets: number
  total_bytes: number
  packets_per_second: number
  bytes_per_second: number
  active_hosts: number
  active_flows: number
  total_flows?: number
  total_hosts?: number
  protocols: Record<string, number>
  extended_protocols: Record<string, number>
  rates: {
    '1s'?: { packets_per_sec: number; bytes_per_sec: number }
    '5s'?: { packets_per_sec: number; bytes_per_sec: number; new_flows_per_sec: number }
    '30s'?: { packets_per_sec: number; bytes_per_sec: number }
  }
  capture_quality: CaptureQualityReport
  recent_alerts_count: number
}

export interface TimeseriesPoint {
  timestamp: number
  iso_time: string
  packets_per_sec: number
  bytes_per_sec: number
}

export interface FlowRecord {
  flow_id: string
  client_ip: string
  client_port: number | null
  server_ip: string
  server_port: number | null
  protocol: string
  first_seen: number
  last_seen: number
  duration: number
  packet_count: number
  byte_count: number
  forward_packets: number
  forward_bytes: number
  reverse_packets: number
  reverse_bytes: number
  tcp_flags_forward: string[]
  tcp_flags_reverse: string[]
  handshake: {
    syn_observed: boolean
    syn_ack_observed: boolean
    ack_observed: boolean
    completed: boolean
    reset_observed: boolean
    fin_observed: boolean
  }
  dns_queries: string[]
  state: 'ACTIVE' | 'CLOSED' | 'TIMED_OUT'
}

export interface HostNode {
  id: string
  ip: string
  sent_bytes: number
  recv_bytes: number
  flows: number
  role: 'client' | 'server' | 'peer'
}

export interface HostEdge {
  source: string
  target: string
  protocol: string
  bytes: number
  packets: number
  flows: number
  last_seen: number
}

export interface HostGraphData {
  nodes: HostNode[]
  edges: HostEdge[]
  disclaimer: string
  top_talkers: Array<{ ip: string; bytes: number }>
}

export interface RuleTrigger {
  rule_id: string
  name: string
  attack_class: string
  description: string
  thresholds: Record<string, string>
  units: Record<string, string>
  measured_values: Record<string, number>
  triggered: boolean
}

export interface AnomalyInfo {
  status: string
  is_anomalous: boolean
  anomaly_score: number | null
  forest_score?: number | null
  max_feature_deviation_sigma?: number | null
  label: string
  note: string
  progress: string
}

export interface EvidencePassport {
  alert_id: string
  timestamp: number
  iso_time: string
  source_ip: string
  destination_ip: string
  protocol: string
  detector_class: 'PORT_SCAN' | 'SYN_FLOOD' | 'TRAFFIC_FLOOD' | 'BENIGN' | 'ANOMALOUS_UNKNOWN_PATTERN' | string
  detector_score: number | null
  is_calibrated: boolean
  decision: 'SUSPECTED' | 'UNCERTAIN' | 'BENIGN'
  model_scope: string
  rule_triggers: RuleTrigger[]
  anomaly: AnomalyInfo
  capture_quality: CaptureQualityReport
  evidence: Record<string, number>
  fragility: {
    status?: string
    advisory_only?: boolean
    reason?: string
    tested_scenarios?: number
    minimum_tested_pairs_to_change?: number | null
    hypothetical_packets?: number
    hypothetical_missing_fraction?: number
    alternative_prediction?: string
    alternative_score?: number
  }
  why_flagged: string
  what_remains_uncertain: string
  recommended_steps: string[]
  provenance: string
}

export interface ReplayExperiment {
  run_id: string
  pcap_name: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  loss_mode: 'random' | 'burst' | 'directional'
  drop_rate: number
  seed: number
  burst_size: number
  burst_interval: number
  drop_ip?: string
  created_at: number
  completed_at?: number
  stability_verdict: 'STABLE' | 'SENSITIVE' | 'INCONCLUSIVE' | 'PENDING'
  baseline_summary: {
    total_windows?: number
    predictions?: Record<string, number>
    mean_features?: Record<string, number>
    fragility_statuses?: Record<string, number>
  }
  perturbed_summary: {
    total_windows?: number
    predictions?: Record<string, number>
    mean_features?: Record<string, number>
    fragility_statuses?: Record<string, number>
  }
  comparison: {
    baseline_windows_count?: number
    perturbed_windows_count?: number
    baseline_suspicious_count?: number
    perturbed_suspicious_count?: number
    decision_shifts?: number
    feature_shifts?: Record<string, {
      baseline: number
      perturbed: number
      difference: number
      percentage_change: number | null
    }>
    fragility_status_comparison?: {
      baseline: Record<string, number>
      perturbed: Record<string, number>
    }
  }
  error?: string
  advisory_disclaimer: string
}

export interface PcapFileInfo {
  filename: string
  relative_path: string
  size_bytes: number
  modified_at: number
  category: string
}

export interface EvaluationData {
  status: 'EVALUATED' | 'NOT_EVALUATED' | 'ERROR'
  message?: string
  scope?: string
  features?: string[]
  threshold?: number
  sklearn_version?: string
  tests?: Record<string, {
    ml: {
      classification: Record<string, any>
      confusion_labels: string[]
      confusion_matrix: number[][]
      false_alerts: number
      benign_observation_seconds: number
      false_alerts_per_hour: number | null
      detection_delays: Array<{ session: string; seconds_from_capture_start: number | null }>
    }
    baseline: Record<string, any>
    fragility: {
      status_counts: Record<string, number>
      sensitive_by_true_class: Record<string, number>
      full_detector_windows_per_second: number
      note: string
    }
    windows: number
    batch_inference_windows_per_second: number
  }>
  disclaimer?: string
}

// ==============================================================================
// Evidence Resilience Engine (ERE) / Lens Types
// ==============================================================================

export interface ScenarioResultItem {
  scenario_id: string
  loss_mode: 'random' | 'burst' | 'directional'
  nominal_drop_rate: number
  seed: number
  burst_size: number
  burst_interval: number
  drop_ip?: string | null
  source_packets: number
  eligible_packets: number
  omitted_packets: number
  retained_packets: number
  realized_omission_rate: number
  eligible_omission_rate: number
  total_windows: number
  matched_windows: number
  baseline_only_windows: number
  perturbed_only_windows: number
  window_alignment_coverage: number
  baseline_suspicious_count: number
  perturbed_suspicious_count: number
  decision_shifts: number
  alert_retention_rate: number
  class_retention_rate: number
  mean_feature_shifts: Record<string, {
    baseline: number
    perturbed: number
    difference: number
    percentage_change: number | null
  }>
  duration_seconds: number
  status: 'completed' | 'cancelled' | 'failed'
  error?: string | null
}

export interface AtlasMatrixCell {
  loss_mode: string
  nominal_rate: string
  runs_count: number
  avg_alert_retention: number
  avg_realized_omission: number
  total_decision_shifts: number
  is_stable: boolean
}

export interface AtlasMatrix {
  modes: string[]
  cells: AtlasMatrixCell[]
}

export interface LowestBoundary {
  scenario_id: string
  loss_mode: string
  nominal_drop_rate: number
  realized_omission_rate: number
  seed: number
  first_affected_window?: string | null
  decision_shifts: number
}

export interface RobustnessEnvelope {
  tested_scenarios_count: number
  baseline_threat_windows: number
  mean_alert_retention_rate: number
  mean_class_retention_rate: number
  total_decision_shifts_across_all_runs: number
  mean_realized_omission_rate: number
  lowest_tested_boundary?: LowestBoundary | null
  tested_loss_modes: string[]
  tested_drop_rates: number[]
  tested_seeds: number[]
  verdict_scope: string
}

export interface RobustnessSweepRun {
  run_id: string
  pcap_name: string
  pcap_sha256: string
  pcap_size_bytes: number
  status: 'queued' | 'running' | 'completed' | 'cancelled' | 'failed'
  created_at: number
  completed_at?: number | null
  total_scenarios: number
  completed_scenarios: number
  current_scenario_id?: string | null
  baseline_summary: {
    total_windows?: number
    predictions?: Record<string, number>
    mean_features?: Record<string, number>
  }
  scenario_results: ScenarioResultItem[]
  atlas_matrix: AtlasMatrix
  envelope: RobustnessEnvelope
  stability_verdict: 'STABLE' | 'SENSITIVE' | 'INCONCLUSIVE' | 'PENDING'
  error?: string | null
}

export interface PassiveRecommendation {
  recommendation_id: string
  title: string
  priority: 'HIGH' | 'MEDIUM' | 'LOW'
  score: number
  trigger_evidence: string
  justifying_scenario?: string | null
  what_to_observe_next: string
  expected_clarification: string
  prerequisites: string
  expected_effort: 'LOW' | 'MEDIUM' | 'HIGH'
  privacy_impact: 'NONE' | 'LOW' | 'MEDIUM'
  rule_id: string
  active_network_action: boolean
}

export interface ObservationPlan {
  plan_id: string
  target_alert_id?: string | null
  status: 'READY' | 'INSUFFICIENT_EVIDENCE' | 'NO_GAPS_IDENTIFIED'
  total_recommendations: number
  recommendations: PassiveRecommendation[]
  evidence_summary: Record<string, any>
  active_network_action: boolean
  disclaimer: string
}

export interface LineageVerifyResult {
  status: 'VALID' | 'INVALID' | 'EMPTY'
  is_valid: boolean
  events_count: number
  head_hash?: string | null
  failing_sequence_id?: number | null
  failing_event_id?: string | null
  error_reason?: string | null
  expected_previous_hash?: string | null
  actual_previous_hash?: string | null
  message?: string | null
}

export interface LineageEvent {
  sequence_id: number
  event_id: string
  event_type: string
  parent_id?: string | null
  timestamp: number
  iso_time: string
  manifest_digest: string
  previous_hash: string
  event_hash: string
  manifest: Record<string, any>
}

export interface EvidenceBundle {
  bundle_version: string
  generated_at: number
  target_identifier: string
  target_event?: LineageEvent | null
  lineage_verification: LineageVerifyResult
  reproducibility_contract: {
    features: string[]
    schema: string
    canonical_serialization: string
    verification_hash_algorithm: string
  }
  security_disclaimer: string
}
