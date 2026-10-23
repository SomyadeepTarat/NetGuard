import React, { useEffect, useState } from 'react'
import {
  AlertTriangle,
  FileText,
  Search,
  Download,
  Info,
  CheckCircle2,
  HelpCircle,
  Shield,
  Eye,
  X
} from 'lucide-react'
import type { EvidencePassport } from '../types'
import { api } from '../api'

export const AlertsView: React.FC = () => {
  const [alerts, setAlerts] = useState<EvidencePassport[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [limit] = useState(25)
  const [classFilter, setClassFilter] = useState<string>('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [search, setSearch] = useState('')
  const [redactIps, setRedactIps] = useState(false)
  const [selectedPassport, setSelectedPassport] = useState<EvidencePassport | null>(null)

  const fetchAlerts = async () => {
    setLoading(true)
    try {
      const res = await api.getAlerts(
        limit,
        page * limit,
        classFilter || undefined,
        severityFilter || undefined,
        search || undefined,
        redactIps
      )
      setAlerts(res.alerts)
      setTotal(res.total)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [page, classFilter, severityFilter, search, redactIps])

  const getClassBadge = (cls: string) => {
    switch (cls) {
      case 'PORT_SCAN':
        return <span className="badge badge-scan">PORT_SCAN</span>
      case 'SYN_FLOOD':
        return <span className="badge badge-syn">SYN_FLOOD</span>
      case 'TRAFFIC_FLOOD':
        return <span className="badge badge-flood">TRAFFIC_FLOOD</span>
      case 'BENIGN':
        return <span className="badge badge-benign">BENIGN</span>
      default:
        return <span className="badge badge-anomaly">{cls}</span>
    }
  }

  return (
    <div>
      {/* Top Filter and Actions Bar */}
      <div className="card" style={{ padding: '14px 18px', marginBottom: '14px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '240px' }}>
            <Search size={16} style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="input-text"
              style={{ width: '100%', maxWidth: '340px' }}
              placeholder="Filter by Alert ID or IP endpoint..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {/* Class filter */}
            <select
              className="select-input"
              value={classFilter}
              onChange={(e) => {
                setClassFilter(e.target.value)
                setPage(0)
              }}
            >
              <option value="">All Detector Classes</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="SYN_FLOOD">SYN Flood</option>
              <option value="TRAFFIC_FLOOD">Traffic Flood</option>
              <option value="ANOMALOUS_UNKNOWN_PATTERN">Anomalous / Unknown</option>
            </select>

            {/* Severity filter */}
            <select
              className="select-input"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
                setPage(0)
              }}
            >
              <option value="">All Decisions</option>
              <option value="SUSPECTED">Suspected Threat</option>
              <option value="UNCERTAIN">Uncertain / Review Needed</option>
            </select>

            {/* Redact IP toggle */}
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--text-secondary)' }}>
              <input
                type="checkbox"
                checked={redactIps}
                onChange={(e) => setRedactIps(e.target.checked)}
              />
              Redact IPs (Demo Safe)
            </label>

            {/* Export buttons */}
            <a href={`/api/alerts/export/json?redact_ips=${redactIps}`} download className="btn btn-secondary">
              <Download size={13} /> JSON
            </a>
            <a href={`/api/alerts/export/csv?redact_ips=${redactIps}`} download className="btn btn-secondary">
              <Download size={13} /> CSV
            </a>
          </div>
        </div>
      </div>

      {/* Incidents List Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Alert Identifier</th>
                <th>Time (UTC)</th>
                <th>Source IP</th>
                <th>Target IP</th>
                <th>Detector Classification</th>
                <th>Uncalibrated Score</th>
                <th>Decision</th>
                <th>Evidence Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    {loading ? 'Querying Evidence Passport repository...' : 'No suspicious incidents recorded matching criteria.'}
                  </td>
                </tr>
              ) : (
                alerts.map((alt) => (
                  <tr key={alt.alert_id}>
                    <td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{alt.alert_id}</td>
                    <td>{alt.iso_time}</td>
                    <td>{alt.source_ip}</td>
                    <td>{alt.destination_ip}</td>
                    <td>{getClassBadge(alt.detector_class)}</td>
                    <td>
                      {alt.detector_score !== null ? (
                        <span>
                          {alt.detector_score.toFixed(3)}{' '}
                          <span style={{ fontSize: '9px', color: 'var(--text-muted)' }}>(score)</span>
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          alt.decision === 'SUSPECTED' ? 'badge-degraded' : 'badge-unknown'
                        }`}
                      >
                        {alt.decision}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          alt.capture_quality?.overall_status === 'HEALTHY'
                            ? 'badge-healthy'
                            : 'badge-degraded'
                        }`}
                      >
                        {alt.capture_quality?.overall_status || 'UNKNOWN'}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '3px 8px', fontSize: '11px' }}
                        onClick={() => setSelectedPassport(alt)}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div
          style={{
            padding: '12px 18px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--text-secondary)',
          }}
        >
          <div>
            Showing {alerts.length} of {total} incidents
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn btn-secondary"
              disabled={page === 0 || loading}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <button
              className="btn btn-secondary"
              disabled={(page + 1) * limit >= total || loading}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Complete Evidence Passport Modal Inspector */}
      {selectedPassport && (
        <div className="modal-overlay" onClick={() => setSelectedPassport(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '850px' }}>
            {/* Passport Header */}
            <div className="passport-header">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileText size={20} style={{ color: 'var(--accent-cyan)' }} />
                  <h2 style={{ fontSize: '17px', fontWeight: 700, letterSpacing: '-0.01em' }}>
                    Incident Evidence Passport: {selectedPassport.alert_id}
                  </h2>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Timestamp: {selectedPassport.iso_time} | Ingestion Provenance: {selectedPassport.provenance}
                </div>
              </div>
              <button
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                onClick={() => setSelectedPassport(null)}
              >
                <X size={20} />
              </button>
            </div>

            {/* Why Flagged (Plain English finding rationale) */}
            <div className="callout callout-advisory" style={{ marginTop: 0, marginBottom: '14px' }}>
              <AlertTriangle size={18} style={{ flexShrink: 0 }} />
              <div>
                <strong>Why Flagged:</strong> {selectedPassport.why_flagged}
              </div>
            </div>

            {/* Two Column Grid */}
            <div className="passport-grid">
              {/* Classification & Model Path */}
              <div className="passport-section">
                <div className="section-title">
                  <Shield size={14} /> 1. Detection Classification
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                  {getClassBadge(selectedPassport.detector_class)}
                  <span className={`badge ${selectedPassport.decision === 'SUSPECTED' ? 'badge-degraded' : 'badge-unknown'}`}>
                    {selectedPassport.decision}
                  </span>
                </div>
                <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                  Classifier Score: {selectedPassport.detector_score !== null ? selectedPassport.detector_score.toFixed(4) : 'N/A'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Calibrated: {selectedPassport.is_calibrated ? 'Yes' : 'No (Uncalibrated score; not attack probability)'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Model Artifact Scope: {selectedPassport.model_scope}
                </div>
              </div>

              {/* Observation & Capture Quality */}
              <div className="passport-section">
                <div className="section-title">
                  <Info size={14} /> 2. Observation Quality Context
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <span className={`badge ${selectedPassport.capture_quality?.overall_status === 'HEALTHY' ? 'badge-healthy' : 'badge-degraded'}`}>
                    {selectedPassport.capture_quality?.overall_status || 'UNKNOWN'}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {selectedPassport.capture_quality?.overall_summary || 'Standard observation channels evaluated.'}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '6px' }}>
                  Queue Drops: {selectedPassport.capture_quality?.indicators?.find((i: any) => i.name.includes('Queue'))?.value ?? 0} | Flow Evictions: {selectedPassport.capture_quality?.indicators?.find((i: any) => i.name.includes('Evictions'))?.value ?? 0}
                </div>
              </div>
            </div>

            {/* Explainable Rule Triggers with Measured Values & Units */}
            <div className="passport-section" style={{ marginBottom: '16px' }}>
              <div className="section-title">
                <CheckCircle2 size={14} /> 3. Transparent Rule Evaluations
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {selectedPassport.rule_triggers.length === 0 ? (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No deterministic rules triggered for this observation window.</div>
                ) : (
                  selectedPassport.rule_triggers.map((rule) => (
                    <div key={rule.rule_id} className="rule-pill triggered">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name} ({rule.rule_id})</span>
                        <span className="badge badge-degraded">TRIGGERED</span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                        {rule.description}
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                        {Object.entries(rule.thresholds).map(([param, thresh]) => (
                          <div key={param}>
                            <span style={{ color: 'var(--text-muted)' }}>{param}:</span>{' '}
                            <span style={{ color: 'var(--accent-rose)' }}>{rule.measured_values[param]}</span>{' '}
                            <span style={{ color: 'var(--text-muted)' }}>({thresh})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Counterfactual Fragility Advisory (if SYN_FLOOD) */}
            {selectedPassport.fragility?.status && selectedPassport.fragility.status !== 'not_applicable' && (
              <div className="passport-section" style={{ marginBottom: '16px', borderColor: 'var(--accent-amber-border)' }}>
                <div className="section-title" style={{ color: 'var(--accent-amber)' }}>
                  <HelpCircle size={14} /> 4. Counterfactual Handshake Sensitivity (Advisory)
                </div>
                <div style={{ fontSize: '12px', marginBottom: '6px' }}>
                  Fragility Status: <strong>{selectedPassport.fragility.status}</strong>
                  {selectedPassport.fragility.minimum_tested_pairs_to_change !== null && (
                    <span>
                      {' '}— {selectedPassport.fragility.minimum_tested_pairs_to_change} hypothetical missing handshake pairs would alter this classification.
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Advisory only: Does not establish actual packet loss or prove that the traffic was benign.
                </div>
              </div>
            )}

            {/* What Remains Uncertain & Recommended Next Steps */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px', marginBottom: '16px' }}>
              <div className="passport-section">
                <div className="section-title">
                  <HelpCircle size={14} /> What Remains Uncertain
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedPassport.what_remains_uncertain}
                </div>
              </div>

              <div className="passport-section">
                <div className="section-title">
                  <Shield size={14} /> Recommended Safe Investigation Steps
                </div>
                <ul style={{ paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {selectedPassport.recommended_steps.map((step, idx) => (
                    <li key={idx} style={{ marginBottom: '4px' }}>
                      {step}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Footer Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedPassport(null)}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
