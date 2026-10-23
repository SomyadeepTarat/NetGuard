import React, { useState, useEffect } from 'react'
import {
  ShieldCheck,
  AlertCircle,
  Eye,
  CheckCircle,
  ShieldAlert
} from 'lucide-react'
import type { EvidencePassport, ObservationPlan, RobustnessSweepRun } from '../types'
import { api } from '../api'

interface Props {
  sweeps: RobustnessSweepRun[]
  activeSweep?: RobustnessSweepRun | null
}

export const NextObservationTab: React.FC<Props> = ({ sweeps, activeSweep }) => {
  const [alerts, setAlerts] = useState<EvidencePassport[]>([])
  const [selectedAlertId, setSelectedAlertId] = useState<string>('')
  const [selectedSweepId, setSelectedSweepId] = useState<string>(activeSweep?.run_id || '')
  const [plan, setPlan] = useState<ObservationPlan | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadAlerts()
  }, [])

  useEffect(() => {
    if (activeSweep?.run_id) {
      setSelectedSweepId(activeSweep.run_id)
    }
  }, [activeSweep?.run_id])

  const loadAlerts = async () => {
    try {
      const res = await api.getAlerts(50, 0)
      setAlerts(res.alerts)
      if (res.alerts.length > 0 && !selectedAlertId) {
        setSelectedAlertId(res.alerts[0].alert_id)
      }
    } catch (e: any) {
      console.error('Failed to load alerts for planner:', e)
    }
  }

  const fetchPlan = async (alertId: string, sweepId?: string) => {
    if (!alertId) return
    setLoading(true)
    setError(null)
    try {
      const res = await api.getAlertObservationPlan(alertId, sweepId || undefined)
      setPlan(res)
    } catch (e: any) {
      setError(e.message || 'Failed to generate observation plan')
      setPlan(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (selectedAlertId) {
      fetchPlan(selectedAlertId, selectedSweepId)
    }
  }, [selectedAlertId, selectedSweepId])

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'HIGH':
        return <span className="badge badge-critical" style={{ fontWeight: 700 }}>HIGH PRIORITY</span>
      case 'MEDIUM':
        return <span className="badge badge-degraded" style={{ fontWeight: 700 }}>MEDIUM PRIORITY</span>
      case 'LOW':
      default:
        return <span className="badge badge-subtle" style={{ fontWeight: 700 }}>LOW PRIORITY</span>
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header & Context Bar */}
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
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--color-text-secondary)', maxWidth: '800px', lineHeight: 1.4 }}>
              Maps verified capture telemetry gaps, directional visibility limitations, and counterfactual sweep instability into an explainable, ranked triage plan for human network analysts.
            </p>
          </div>
        </div>

        {/* Target Alert & Correlated Sweep Selector */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', background: 'var(--color-surface-hover)', padding: '14px', borderRadius: 'var(--radius-md)' }}>
          <div>
            <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
              Target Threat Incident (Evidence Passport)
            </label>
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
              {alerts.map((alt) => (
                <option key={alt.alert_id} value={alt.alert_id}>
                  [{alt.detector_class}] {alt.source_ip} → {alt.destination_ip} ({alt.alert_id})
                </option>
              ))}
              {alerts.length === 0 && <option value="">No incidents recorded in repository</option>}
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
              Correlated Robustness Sweep (Optional Context)
            </label>
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
              <option value="">None (Evaluate Capture Quality & Rules Only)</option>
              {sweeps.map((s) => (
                <option key={s.run_id} value={s.run_id}>
                  {s.pcap_name} ({s.stability_verdict} • {s.completed_scenarios} runs)
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Plan Output */}
      {error && (
        <div className="card" style={{ padding: '20px', borderColor: 'var(--color-critical-border)', background: 'var(--color-critical-bg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-critical)' }}>
            <AlertCircle size={16} />
            <span style={{ fontSize: '13px', fontWeight: 600 }}>{error}</span>
          </div>
        </div>
      )}

      {loading && (
        <div className="card" style={{ padding: '40px 20px', textAlign: 'center' }}>
          <div style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}>Evaluating evidence gaps and generating ranked triage plan...</div>
        </div>
      )}

      {!loading && plan && (
        <>
          {/* Summary Banner */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {plan.total_recommendations} Prioritized Actions for Analyst
              </span>
              <span className="badge badge-subtle" style={{ fontFamily: 'var(--font-mono)' }}>
                {plan.plan_id}
              </span>
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
              Deterministic Rule Engine • Traceable Rule IDs
            </div>
          </div>

          {/* Recommendations List */}
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
                      ? 'var(--color-warning)'
                      : 'var(--color-border)'
                  }`
                }}
              >
                {/* Header */}
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
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                  gap: '12px',
                  background: 'var(--color-surface-hover)',
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  marginBottom: '14px',
                  fontSize: '12px'
                }}>
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

                {/* Bottom Operational Metadata */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                  <div>
                    <strong>Prerequisites:</strong> {rec.prerequisites}
                  </div>
                  <div style={{ display: 'flex', gap: '12px' }}>
                    <span><strong>Effort:</strong> {rec.expected_effort}</span>
                    <span><strong>Privacy Impact:</strong> {rec.privacy_impact}</span>
                  </div>
                </div>
              </div>
            ))}

            {plan.recommendations.length === 0 && (
              <div className="card" style={{ padding: '40px 20px', textAlign: 'center' }}>
                <CheckCircle size={32} style={{ color: 'var(--color-healthy)', margin: '0 auto 12px' }} />
                <h4 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                  No Significant Evidence Gaps Identified
                </h4>
                <p style={{ fontSize: '12.5px', color: 'var(--color-text-secondary)', maxWidth: '420px', margin: '0 auto' }}>
                  The capture quality indicators show full packet retention, bidirectional visibility is satisfied, and the detector finding remained robust.
                </p>
              </div>
            )}
          </div>
        </>
      )}

      {alerts.length === 0 && !loading && (
        <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
          <ShieldAlert size={36} style={{ color: 'var(--color-text-muted)', margin: '0 auto 16px' }} />
          <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
            No Incidents Available for Planning
          </h3>
          <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)', maxWidth: '440px', margin: '0 auto' }}>
            Run synthetic traffic or an offline replay to detect an incident and generate an Evidence Passport.
          </p>
        </div>
      )}
    </div>
  )
}
