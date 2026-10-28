import React, { useState, useEffect } from 'react'
import {
  ShieldCheck,
  AlertCircle,
  Eye,
  CheckCircle,
  ShieldAlert,
  Compass,
  FileSearch,
  Info,
  RefreshCw
} from 'lucide-react'
import type { EvidencePassport, ObservationPlan, RobustnessSweepRun } from '../types'
import { api } from '../api'

interface Props {
  sweeps?: RobustnessSweepRun[]
  activeSweep?: RobustnessSweepRun | null
  onRefreshSweeps?: () => void
}

export const NextObservationTab: React.FC<Props> = ({ sweeps = [], activeSweep, onRefreshSweeps }) => {
  const [alerts, setAlerts] = useState<EvidencePassport[]>([])
  const [internalSweeps, setInternalSweeps] = useState<RobustnessSweepRun[]>(sweeps)
  const [selectedAlertId, setSelectedAlertId] = useState<string>('')
  const [selectedSweepId, setSelectedSweepId] = useState<string>(activeSweep?.run_id || '')
  const [plan, setPlan] = useState<ObservationPlan | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [analyzingPcap, setAnalyzingPcap] = useState(false)
  const [analyzeMsg, setAnalyzeMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Use effective sweeps combining props and internal fetch
  const effectiveSweeps = sweeps.length > 0 ? sweeps : internalSweeps

  useEffect(() => {
    loadAlertsAndSweeps()
  }, [])

  useEffect(() => {
    if (sweeps.length > 0) {
      setInternalSweeps(sweeps)
    }
  }, [sweeps])

  useEffect(() => {
    if (activeSweep?.run_id) {
      setSelectedSweepId(activeSweep.run_id)
    }
  }, [activeSweep?.run_id])

  const loadAlertsAndSweeps = async () => {
    try {
      const [alertsRes, sweepsRes] = await Promise.all([
        api.getAlerts(50, 0).catch(() => ({ alerts: [], total: 0 })),
        api.listRobustnessSweeps().catch(() => [] as RobustnessSweepRun[])
      ])

      setAlerts(alertsRes.alerts)
      setInternalSweeps(sweepsRes)
      if (onRefreshSweeps) onRefreshSweeps()

      // Set initial selections
      if (alertsRes.alerts.length > 0 && !selectedAlertId) {
        setSelectedAlertId(alertsRes.alerts[0].alert_id)
      } else if (alertsRes.alerts.length === 0 && sweepsRes.length > 0 && !selectedSweepId) {
        // Mode B default: select first available sweep if no alerts exist
        setSelectedSweepId(sweepsRes[0].run_id)
      }
    } catch (e: any) {
      console.error('Failed to load initial data for Next Observation planner:', e)
    }
  }

  const fetchPlan = async (alertId?: string, sweepId?: string) => {
    if (!alertId && !sweepId) {
      setPlan(null)
      return
    }

    setLoading(true)
    setError(null)
    try {
      let res: ObservationPlan
      if (alertId) {
        // Mode A: Incident-linked planning (optional correlated sweep)
        res = await api.getAlertObservationPlan(alertId, sweepId || undefined)
      } else if (sweepId) {
        // Mode B: Sweep-only advisory planning (no Evidence Passport)
        res = await api.getSweepObservationPlan(sweepId)
      } else {
        res = await api.getObservationPlan({})
      }
      setPlan(res)
    } catch (e: any) {
      setError(e.message || 'Failed to generate observation plan')
      setPlan(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPlan(selectedAlertId, selectedSweepId)
  }, [selectedAlertId, selectedSweepId])

  const handleAnalyzeDemoPcap = async () => {
    setAnalyzingPcap(true)
    setAnalyzeMsg(null)
    try {
      const res = await api.analyzePcap('artifacts/demo/test-SYN_FLOOD-0.pcap')
      setAnalyzeMsg({
        type: 'success',
        text: `Analysis complete: ${res.incidents_recorded} genuine incident(s) recorded in repository from detector findings.`
      })
      const alertsRes = await api.getAlerts(50, 0)
      setAlerts(alertsRes.alerts)
      if (alertsRes.alerts.length > 0) {
        setSelectedAlertId(alertsRes.alerts[0].alert_id)
      }
    } catch (e: any) {
      setAnalyzeMsg({
        type: 'error',
        text: `PCAP analysis failed: ${e.message || String(e)}`
      })
    } finally {
      setAnalyzingPcap(false)
    }
  }

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'HIGH':
        return <span className="badge badge-critical" style={{ fontWeight: 700 }}>HIGH PRIORITY</span>
      case 'MEDIUM':
        return <span className="badge badge-warning" style={{ fontWeight: 700 }}>MEDIUM PRIORITY</span>
      case 'LOW':
      default:
        return <span className="badge badge-subtle" style={{ fontWeight: 700 }}>LOW PRIORITY</span>
    }
  }

  const currentMode = selectedAlertId ? 'MODE_A' : (selectedSweepId ? 'MODE_B' : 'UNSELECTED')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header & Mode Context */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <Eye size={18} style={{ color: 'var(--color-accent)' }} />
              <h2 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Passive Next-Observation Planner
              </h2>
              <span className="badge badge-healthy" style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <ShieldCheck size={12} /> PASSIVE ONLY — NO PACKETS TRANSMITTED
              </span>
              {currentMode === 'MODE_A' && (
                <span className="badge badge-accent" style={{ fontSize: '11px' }}>
                  MODE A: INCIDENT-LINKED
                </span>
              )}
              {currentMode === 'MODE_B' && (
                <span className="badge badge-warning" style={{ fontSize: '11px' }}>
                  MODE B: SWEEP-ONLY ADVISORY
                </span>
              )}
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--color-text-secondary)', maxWidth: '820px', lineHeight: 1.4 }}>
              Maps verified capture telemetry gaps, directional visibility limitations, and counterfactual sweep instability into an explainable, ranked triage plan for human network analysts.
            </p>
          </div>

          <button
            onClick={() => loadAlertsAndSweeps()}
            className="btn btn-secondary"
            style={{ fontSize: '11.5px', padding: '6px 10px', display: 'flex', alignItems: 'center', gap: '6px' }}
            title="Refresh incidents and sweeps from backend"
          >
            <RefreshCw size={13} /> Refresh Sources
          </button>
        </div>

        {/* Offline PCAP Ingestion Assistant when repository has no incidents */}
        {alerts.length === 0 && (
          <div
            style={{
              background: 'var(--color-surface-hover)',
              border: '1px solid var(--color-warning-border, #d97706)',
              borderRadius: 'var(--radius-md)',
              padding: '14px 16px',
              marginBottom: '16px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: '16px'
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <Info size={16} style={{ color: 'var(--color-warning, #d97706)' }} />
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  No Incidents Recorded in Repository (Mode B Active)
                </span>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--color-text-secondary)', margin: 0 }}>
                You can generate a <strong>Mode B (Sweep-Only Advisory)</strong> plan using completed robustness sweeps below, or analyze an offline PCAP to record a genuine Evidence Passport.
              </p>
            </div>
            <button
              onClick={handleAnalyzeDemoPcap}
              disabled={analyzingPcap}
              className="btn btn-primary"
              style={{
                fontSize: '12px',
                padding: '8px 14px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                whiteSpace: 'nowrap'
              }}
            >
              {analyzingPcap ? (
                <>
                  <RefreshCw size={14} className="spin" /> Analyzing PCAP...
                </>
              ) : (
                <>
                  <FileSearch size={14} /> Analyze Demo PCAP (test-SYN_FLOOD)
                </>
              )}
            </button>
          </div>
        )}

        {analyzeMsg && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: 'var(--radius-sm)',
              marginBottom: '16px',
              fontSize: '12.5px',
              background: analyzeMsg.type === 'success' ? 'var(--color-healthy-bg)' : 'var(--color-critical-bg)',
              color: analyzeMsg.type === 'success' ? 'var(--color-healthy)' : 'var(--color-critical)',
              border: `1px solid ${analyzeMsg.type === 'success' ? 'var(--color-healthy-border)' : 'var(--color-critical-border)'}`
            }}
          >
            {analyzeMsg.text}
          </div>
        )}

        {/* Dual Mode Selectors: Target Alert & Correlated Sweep Selector */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', background: 'var(--color-surface-hover)', padding: '14px', borderRadius: 'var(--radius-md)' }}>
          {/* Column 1: Target Threat Incident */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                Target Threat Incident (Evidence Passport)
              </label>
              {selectedAlertId ? (
                <span className="badge badge-accent" style={{ fontSize: '10px' }}>MODE A: LINKED</span>
              ) : (
                <span className="badge badge-subtle" style={{ fontSize: '10px' }}>OPTIONAL</span>
              )}
            </div>
            <select
              value={selectedAlertId}
              onChange={(e) => setSelectedAlertId(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--color-border)',
                background: 'var(--color-surface)',
                color: 'var(--color-text-primary)',
                fontSize: '12.5px',
                fontFamily: 'var(--font-mono)'
              }}
            >
              <option value="">None (Mode B: Sweep-Only Advisory Mode)</option>
              {alerts.map((alt) => (
                <option key={alt.alert_id} value={alt.alert_id}>
                  [{alt.detector_class}] {alt.source_ip} → {alt.destination_ip} ({alt.alert_id})
                </option>
              ))}
            </select>
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
              {selectedAlertId
                ? 'Evaluating capture quality indicators, protocol fragility, and detector triggers.'
                : 'Select an incident for Mode A, or leave as "None" for Mode B sweep advisory.'}
            </div>
          </div>

          {/* Column 2: Correlated Robustness Sweep */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                Robustness Sweep Selection
              </label>
              <span className="badge badge-subtle" style={{ fontSize: '10px' }}>
                {effectiveSweeps.length} Available
              </span>
            </div>
            <select
              value={selectedSweepId}
              onChange={(e) => setSelectedSweepId(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 10px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--color-border)',
                background: 'var(--color-surface)',
                color: 'var(--color-text-primary)',
                fontSize: '12.5px',
                fontFamily: 'var(--font-mono)'
              }}
            >
              {selectedAlertId ? (
                <option value="">None (Evaluate Incident Quality & Rules Only)</option>
              ) : (
                <option value="">Select a completed robustness sweep...</option>
              )}
              {effectiveSweeps.map((s) => (
                <option key={s.run_id} value={s.run_id}>
                  {s.pcap_name} ({s.stability_verdict} • {s.completed_scenarios} scenarios • {s.run_id})
                </option>
              ))}
            </select>
            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '4px' }}>
              {selectedSweepId
                ? 'Incorporating perturbation matrix decision shifts, directional sensitivity, and boundary.'
                : (selectedAlertId ? 'Optional: Correlate a completed sweep to evaluate decision shifts.' : 'Select a completed sweep to generate a Mode B advisory plan.')}
            </div>
          </div>
        </div>
      </div>

      {/* Plan Errors */}
      {error && (
        <div className="card" style={{ padding: '20px', borderColor: 'var(--color-critical-border)', background: 'var(--color-critical-bg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-critical)' }}>
            <AlertCircle size={16} />
            <span style={{ fontSize: '13px', fontWeight: 600 }}>{error}</span>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="card" style={{ padding: '40px 20px', textAlign: 'center' }}>
          <RefreshCw size={24} className="spin" style={{ color: 'var(--color-accent)', margin: '0 auto 12px' }} />
          <div style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}>
            Evaluating evidence gaps and generating ranked passive triage plan...
          </div>
        </div>
      )}

      {/* Plan Output */}
      {!loading && plan && (
        <>
          {/* Mode B Explicit Notice / Disclaimer Callout */}
          {plan.plan_mode === 'SWEEP_ONLY_ADVISORY' && (
            <div
              style={{
                background: 'rgba(217, 119, 6, 0.08)',
                border: '1px solid rgba(217, 119, 6, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '14px 18px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px'
              }}
            >
              <Info size={18} style={{ color: '#d97706', marginTop: '2px', flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#d97706', marginBottom: '3px' }}>
                  SWEEP-ONLY ADVISORY PLAN — NO EVIDENCE PASSPORT LINKED
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-primary)', lineHeight: 1.4 }}>
                  Recommendations are derived strictly from counterfactual robustness sweep instability. No confirmed threat incident or live capture-quality passport is associated with this plan. No fake incident or fabricated passport was generated.
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                  Target Sweep: {plan.target_sweep_id || 'N/A'} • Completed Scenarios: {plan.evidence_summary?.completed_scenarios ?? 'N/A'} • Verdict: {plan.evidence_summary?.sweep_stability ?? 'N/A'}
                </div>
              </div>
            </div>
          )}

          {/* Mode A Target Incident Callout */}
          {plan.plan_mode === 'INCIDENT_LINKED' && (
            <div
              style={{
                background: 'rgba(59, 130, 246, 0.08)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: 'var(--radius-md)',
                padding: '14px 18px',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px'
              }}
            >
              <ShieldCheck size={18} style={{ color: '#3b82f6', marginTop: '2px', flexShrink: 0 }} />
              <div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#3b82f6', marginBottom: '3px' }}>
                  INCIDENT-LINKED EVIDENCE PLAN — VERIFIED EVIDENCE PASSPORT
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-primary)', lineHeight: 1.4 }}>
                  Recommendations originate from actual recorded telemetry, kernel drop indicators, flow state evictions, and optional counterfactual sweep correlation.
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-text-secondary)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                  Target Incident: {plan.target_alert_id || 'N/A'} {plan.target_sweep_id ? `• Correlated Sweep: ${plan.target_sweep_id}` : '• No Correlated Sweep'}
                </div>
              </div>
            </div>
          )}

          {/* Insufficient Evidence Explicit State */}
          {plan.status === 'INSUFFICIENT_EVIDENCE' && (
            <div className="card" style={{ padding: '40px 20px', textAlign: 'center' }}>
              <ShieldAlert size={36} style={{ color: 'var(--color-critical)', margin: '0 auto 12px' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                Insufficient Evidence for Advisory Planning
              </h3>
              <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)', maxWidth: '520px', margin: '0 auto 16px' }}>
                {plan.insufficient_reason || 'Neither an Evidence Passport nor a completed Robustness Sweep with sufficient scenarios was provided.'}
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
                <button
                  onClick={handleAnalyzeDemoPcap}
                  disabled={analyzingPcap}
                  className="btn btn-primary"
                  style={{ fontSize: '12px' }}
                >
                  Analyze Demo PCAP to Create Incident
                </button>
              </div>
            </div>
          )}

          {/* Summary Banner */}
          {plan.status !== 'INSUFFICIENT_EVIDENCE' && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  {plan.total_recommendations} Prioritized Actions for Analyst
                </span>
                <span className="badge badge-subtle" style={{ fontFamily: 'var(--font-mono)' }}>
                  {plan.plan_id}
                </span>
                <span className="badge badge-healthy" style={{ fontSize: '10.5px' }}>
                  active_network_action: false
                </span>
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                Deterministic Rule Engine • Traceable Rule IDs
              </div>
            </div>
          )}

          {/* Recommendations List */}
          {plan.status !== 'INSUFFICIENT_EVIDENCE' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {plan.recommendations.map((rec, index) => (
                <div
                  key={rec.recommendation_id}
                  className="card"
                  style={{
                    padding: '20px',
                    borderLeft: `4px solid ${
                      rec.priority === 'HIGH'
                        ? 'var(--color-critical)'
                        : rec.priority === 'MEDIUM'
                        ? 'var(--color-warning, #d97706)'
                        : 'var(--color-border)'
                    }`
                  }}
                >
                  {/* Card Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div
                        style={{
                          width: '26px',
                          height: '26px',
                          borderRadius: '50%',
                          background: 'var(--color-surface-muted)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '12px',
                          fontWeight: 700,
                          color: 'var(--color-text-primary)',
                          fontFamily: 'var(--font-mono)'
                        }}
                      >
                        {index + 1}
                      </div>
                      <div>
                        <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                          {rec.title}
                        </h3>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          Rule ID: {rec.rule_id} • Score: {rec.score}/100 • {rec.recommendation_id}
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {getPriorityBadge(rec.priority)}
                      <span className="badge badge-healthy" style={{ fontSize: '10.5px' }}>
                        PASSIVE CHECK
                      </span>
                    </div>
                  </div>

                  {/* Evidence Trace Grid */}
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '12px',
                      background: 'var(--color-surface-hover)',
                      padding: '12px',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: '14px',
                      fontSize: '12px'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: '3px' }}>
                        Triggering Evidence Gap
                      </div>
                      <div style={{ color: 'var(--color-text-primary)', lineHeight: 1.35 }}>
                        {rec.trigger_evidence}
                      </div>
                    </div>

                    {rec.justifying_scenario && (
                      <div>
                        <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: '3px' }}>
                          Justifying Robustness Scenario
                        </div>
                        <div style={{ color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
                          {rec.justifying_scenario}
                        </div>
                      </div>
                    )}

                    <div>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: '3px' }}>
                        Recommended Passive Action
                      </div>
                      <div style={{ color: 'var(--color-text-primary)', fontWeight: 500, lineHeight: 1.35 }}>
                        {rec.what_to_observe_next}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', marginBottom: '3px' }}>
                        Expected Clarification
                      </div>
                      <div style={{ color: 'var(--color-text-primary)', lineHeight: 1.35 }}>
                        {rec.expected_clarification}
                      </div>
                    </div>
                  </div>

                  {/* Operational Metadata Footer */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                    <div>
                      <strong>Prerequisites:</strong> {rec.prerequisites}
                    </div>
                    <div style={{ display: 'flex', gap: '12px' }}>
                      <span><strong>Effort:</strong> {rec.expected_effort}</span>
                      <span><strong>Privacy Impact:</strong> {rec.privacy_impact}</span>
                      <span><strong>Network Probe:</strong> None (Passive)</span>
                    </div>
                  </div>
                </div>
              ))}

              {plan.recommendations.length === 0 && plan.status === 'NO_GAPS_IDENTIFIED' && (
                <div className="card" style={{ padding: '40px 20px', textAlign: 'center' }}>
                  <CheckCircle size={32} style={{ color: 'var(--color-healthy)', margin: '0 auto 12px' }} />
                  <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                    No Significant Evidence Gaps Identified
                  </h4>
                  <p style={{ fontSize: '12.5px', color: 'var(--color-text-secondary)', maxWidth: '440px', margin: '0 auto' }}>
                    The capture quality indicators show full packet retention, bidirectional visibility is satisfied, and the detector finding remained robust under counterfactual testing.
                  </p>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* When neither alert nor sweep is selected */}
      {!loading && !plan && !error && (
        <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
          <Compass size={36} style={{ color: 'var(--color-text-muted)', margin: '0 auto 16px' }} />
          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
            Select an Incident or Robustness Sweep
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)', maxWidth: '440px', margin: '0 auto 16px' }}>
            Choose a Target Threat Incident above for <strong>Mode A (Incident-Linked)</strong> planning, or choose a Correlated Robustness Sweep for <strong>Mode B (Sweep-Only Advisory)</strong> planning.
          </p>
          {alerts.length === 0 && (
            <button
              onClick={handleAnalyzeDemoPcap}
              disabled={analyzingPcap}
              className="btn btn-secondary"
              style={{ fontSize: '12px', margin: '0 auto' }}
            >
              Analyze Demo PCAP to Populate Incident Repository
            </button>
          )}
        </div>
      )}
    </div>
  )
}
