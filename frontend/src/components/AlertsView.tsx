import React, { useEffect, useState } from 'react'
import {
  AlertTriangle,
  FileText,
  Search,
  Download,
  CheckCircle2,
  Shield,
  Eye,
  X,
  RefreshCw,
  Sliders,
  Activity,
  Layers
} from 'lucide-react'
import type { EvidencePassport } from '../types'
import { api } from '../api'
import { FusionEvidence } from './FusionPanel'
import { PageHeader } from './PageHeader'

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
      console.error('Failed to query Evidence Passports:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [page, limit, classFilter, severityFilter, search, redactIps])

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

  const handleResetFilters = () => {
    setSearch('')
    setClassFilter('')
    setSeverityFilter('')
    setPage(0)
  }

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Alerts & Evidence Passports"
        description="Auditable incident records correlating deterministic rule triggers, ML classifier scores, capture-quality context, and counterfactual fragility."
        icon={<AlertTriangle size={20} />}
        badge={
          <span className="badge badge-healthy">
            {total} Incident Passports Stored
          </span>
        }
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <a
              href={`/api/alerts/export/json?redact_ips=${redactIps}`}
              download
              className="btn btn-secondary"
              title="Export all evidence records as structured JSON"
            >
              <Download size={13} /> JSON
            </a>
            <a
              href={`/api/alerts/export/csv?redact_ips=${redactIps}`}
              download
              className="btn btn-secondary"
              title="Export all evidence records as flat CSV"
            >
              <Download size={13} /> CSV
            </a>
            <button
              className="btn btn-secondary"
              onClick={fetchAlerts}
              disabled={loading}
              title="Refresh alerts"
            >
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
        }
      />

      {/* Filter and Query Toolbar */}
      <div className="card" style={{ padding: '14px 18px', marginBottom: '18px' }}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
          }}
        >
          {/* Search Box */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              flex: 1,
              minWidth: '260px',
              position: 'relative',
            }}
          >
            <Search
              size={15}
              style={{
                position: 'absolute',
                left: '10px',
                color: 'var(--color-text-muted)',
              }}
            />
            <input
              type="text"
              className="input-text"
              style={{ width: '100%', paddingLeft: '32px' }}
              placeholder="Search by Alert ID, source IP, or target IP..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{
                  position: 'absolute',
                  right: '10px',
                  background: 'none',
                  border: 'none',
                  color: 'var(--color-text-muted)',
                  cursor: 'pointer',
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Filters & Redact Toggle */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              flexWrap: 'wrap',
            }}
          >
            {/* Detector Class Filter */}
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

            {/* Severity / Decision Filter */}
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

            {/* Redact IP Toggle */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                cursor: 'pointer',
                color: 'var(--color-text-secondary)',
                userSelect: 'none',
              }}
            >
              <input
                type="checkbox"
                checked={redactIps}
                onChange={(e) => setRedactIps(e.target.checked)}
                style={{ accentColor: 'var(--color-accent)' }}
              />
              <span>Pseudonymize IPs</span>
            </label>
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
                <th>Observed Timestamp</th>
                <th>Endpoints (Source → Target)</th>
                <th>Classification</th>
                <th>Detector Score</th>
                <th>Decision</th>
                <th>Capture Quality</th>
                <th style={{ textAlign: 'right' }}>Evidence Passport</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '48px 20px' }}>
                    {loading ? (
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '10px',
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--color-accent)' }} />
                        <span>Querying Evidence Passport repository...</span>
                      </div>
                    ) : (
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '10px',
                        }}
                      >
                        <div
                          style={{
                            width: '42px',
                            height: '42px',
                            borderRadius: '50%',
                            background: 'var(--color-surface-muted)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'var(--color-text-muted)',
                          }}
                        >
                          <FileText size={22} />
                        </div>
                        <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                          No Incident Passports Recorded
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', maxWidth: '440px', lineHeight: 1.5 }}>
                          {search || classFilter || severityFilter
                            ? 'No incident records match the active filter criteria.'
                            : 'Evidence Passports are generated when deterministic rule triggers or ML classifier confidence thresholds are reached. No anomalies or attacks have been flagged in this session.'}
                        </div>
                        {(search || classFilter || severityFilter) && (
                          <button
                            className="btn btn-secondary"
                            onClick={handleResetFilters}
                            style={{ marginTop: '4px' }}
                          >
                            Reset Filter Criteria
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                alerts.map((alt) => {
                  const isSelected = selectedPassport?.alert_id === alt.alert_id
                  return (
                    <tr
                      key={alt.alert_id}
                      className={`table-row-clickable ${isSelected ? 'table-row-selected' : ''}`}
                      onClick={() => setSelectedPassport(alt)}
                      title="Click to inspect complete 9-section Evidence Passport"
                    >
                      {/* Alert ID */}
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-accent)' }}>
                        {alt.alert_id}
                      </td>

                      {/* Time */}
                      <td style={{ color: 'var(--color-text-secondary)', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                        {alt.iso_time}
                      </td>

                      {/* Endpoints */}
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        <span>{alt.source_ip}</span>
                        <span style={{ color: 'var(--color-text-muted)', margin: '0 6px' }}>→</span>
                        <span>{alt.destination_ip}</span>
                      </td>

                      {/* Classification */}
                      <td>{getClassBadge(alt.detector_class)}</td>

                      {/* Detector Score */}
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        {alt.detector_score !== null ? (
                          <span>
                            {alt.detector_score.toFixed(3)}{' '}
                            <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
                              ({alt.is_calibrated ? 'calibrated' : 'score'})
                            </span>
                          </span>
                        ) : (
                          <span style={{ color: 'var(--color-text-muted)' }}>N/A</span>
                        )}
                      </td>

                      {/* Decision */}
                      <td>
                        <span
                          className={`badge ${
                            alt.decision === 'SUSPECTED' ? 'badge-degraded' : 'badge-unknown'
                          }`}
                        >
                          {alt.decision}
                        </span>
                      </td>

                      {/* Evidence Quality */}
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

                      {/* Action */}
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '3px 8px', fontSize: '11px' }}
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedPassport(alt)
                          }}
                        >
                          <Eye size={12} /> Inspect
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div
          style={{
            padding: '12px 18px',
            borderTop: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--color-text-secondary)',
            background: 'var(--color-surface)',
          }}
        >
          <div>
            Showing {alerts.length} of {total} incidents (Page {page + 1})
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
        <div className="modal-backdrop" onClick={() => setSelectedPassport(null)}>
          <div
            className="modal-card"
            style={{ maxWidth: '880px', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Passport Header */}
            <div
              style={{
                padding: '18px 24px',
                borderBottom: '1px solid var(--color-border)',
                background: 'var(--color-surface-hover)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileText size={18} style={{ color: 'var(--color-accent)' }} />
                  <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                    Evidence Passport: {selectedPassport.alert_id}
                  </h2>
                  {getClassBadge(selectedPassport.detector_class)}
                  <span
                    className={`badge ${
                      selectedPassport.decision === 'SUSPECTED' ? 'badge-degraded' : 'badge-unknown'
                    }`}
                  >
                    {selectedPassport.decision}
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                  Timestamp: {selectedPassport.iso_time} | Provenance: {selectedPassport.provenance}
                </div>
              </div>
              <button
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--color-text-secondary)',
                  cursor: 'pointer',
                  padding: '4px',
                }}
                onClick={() => setSelectedPassport(null)}
                aria-label="Close passport"
              >
                <X size={18} />
              </button>
            </div>

            {/* Passport Scrollable Body */}
            <div style={{ padding: '24px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* 1. Plain English Rationale: Why Flagged */}
              <div className="callout callout-advisory" style={{ marginTop: 0, marginBottom: 0 }}>
                <AlertTriangle size={18} style={{ flexShrink: 0 }} />
                <div>
                  <strong>Why Flagged:</strong> {selectedPassport.why_flagged}
                  {selectedPassport.what_remains_uncertain && (
                    <div style={{ marginTop: '4px', color: 'var(--color-text-secondary)' }}>
                      <strong>Uncertainty Boundary:</strong> {selectedPassport.what_remains_uncertain}
                    </div>
                  )}
                </div>
              </div>

              {/* 2. Top Metric Cards: Classification & Quality */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                {/* Detection Classification */}
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Shield size={14} style={{ color: 'var(--color-accent)' }} />
                      Detection Classification
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>Classifier Score:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {selectedPassport.detector_score !== null
                          ? selectedPassport.detector_score.toFixed(4)
                          : 'N/A'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>Calibration Status:</span>
                      <span style={{ color: 'var(--color-text-muted)' }}>
                        {selectedPassport.is_calibrated
                          ? 'Calibrated Probability'
                          : 'Uncalibrated score (not attack probability)'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>Model Artifact Scope:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                        {selectedPassport.model_scope}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Observation Quality Context */}
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Activity size={14} style={{ color: 'var(--color-healthy)' }} />
                      Observation Quality Context
                    </div>
                    <span
                      className={`badge ${
                        selectedPassport.capture_quality?.overall_status === 'HEALTHY'
                          ? 'badge-healthy'
                          : 'badge-degraded'
                      }`}
                    >
                      {selectedPassport.capture_quality?.overall_status || 'UNKNOWN'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                    {selectedPassport.capture_quality?.overall_summary ||
                      'Standard observation channel evaluated without loss.'}
                  </div>
                  <div
                    style={{
                      marginTop: '8px',
                      paddingTop: '6px',
                      borderTop: '1px solid var(--color-border-subtle)',
                      display: 'flex',
                      gap: '12px',
                      fontSize: '11px',
                      color: 'var(--color-text-muted)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    <span>
                      Drops:{' '}
                      {selectedPassport.capture_quality?.indicators?.find((i: any) =>
                        i.name.includes('Queue')
                      )?.value ?? 0}
                    </span>
                    <span>
                      Evictions:{' '}
                      {selectedPassport.capture_quality?.indicators?.find((i: any) =>
                        i.name.includes('Evictions')
                      )?.value ?? 0}
                    </span>
                  </div>
                </div>
              </div>

              {/* 3. Transparent Rule Evaluations */}
              <div className="card" style={{ padding: '16px' }}>
                <div className="card-header" style={{ marginBottom: '12px', paddingBottom: '8px' }}>
                  <div className="card-title" style={{ fontSize: '13px' }}>
                    <CheckCircle2 size={15} style={{ color: 'var(--color-accent)' }} />
                    Deterministic Rule Evaluations
                  </div>
                </div>
                {selectedPassport.rule_triggers.length === 0 ? (
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    No deterministic threshold rules triggered for this incident window. Finding was raised through model classification or anomaly baseline.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {selectedPassport.rule_triggers.map((rule) => (
                      <div
                        key={rule.rule_id}
                        style={{
                          padding: '10px 14px',
                          background: 'var(--color-surface-hover)',
                          border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', fontSize: '12.5px' }}>
                            {rule.name} ({rule.rule_id})
                          </span>
                          <span className="badge badge-degraded">TRIGGERED</span>
                        </div>
                        <div style={{ fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '8px' }}>
                          {rule.description}
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '14px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                          {Object.entries(rule.thresholds).map(([param, thresh]) => (
                            <div key={param}>
                              <span style={{ color: 'var(--color-text-muted)' }}>{param}: </span>
                              <span style={{ color: 'var(--color-critical)', fontWeight: 600 }}>
                                {rule.measured_values[param]}
                              </span>
                              <span style={{ color: 'var(--color-text-muted)' }}> (threshold: {thresh})</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 4. Engineered Traffic Features */}
              <div className="card" style={{ padding: '16px' }}>
                <div className="card-header" style={{ marginBottom: '12px', paddingBottom: '8px' }}>
                  <div className="card-title" style={{ fontSize: '13px' }}>
                    <Sliders size={15} style={{ color: 'var(--color-accent)' }} />
                    Extracted Traffic Features (Observation Window)
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '10px' }}>
                  {Object.entries(selectedPassport.evidence || {}).map(([key, val]) => (
                    <div
                      key={key}
                      style={{
                        padding: '8px 10px',
                        background: 'var(--color-surface-hover)',
                        border: '1px solid var(--color-border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                      }}
                    >
                      <div style={{ fontSize: '10.5px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {key}
                      </div>
                      <div style={{ fontSize: '13px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', marginTop: '2px' }}>
                        {typeof val === 'number' ? val.toFixed(4).replace(/\.?0+$/, '') : val}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {selectedPassport.research_fusion?.status && (
                <section className="card" style={{ padding: 16 }}>
                  <h3 className="card-title" style={{ marginBottom: 12 }}>Observation-aware fusion evidence</h3>
                  <FusionEvidence result={selectedPassport.research_fusion} />
                </section>
              )}

              {/* 5. Anomaly Baseline Detector Status */}
              {selectedPassport.anomaly && (
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Activity size={14} style={{ color: '#7c3aed' }} />
                      Anomaly Detection Status
                    </div>
                    <span className="badge badge-anomaly">
                      {selectedPassport.anomaly.is_anomalous ? 'ANOMALOUS' : 'WITHIN_BASELINE'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '8px' }}>
                    {selectedPassport.anomaly.note}
                  </div>
                  <div style={{ display: 'flex', gap: '14px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                    <span>Status: {selectedPassport.anomaly.status}</span>
                    <span>Label: {selectedPassport.anomaly.label}</span>
                  </div>
                </div>
              )}

              {/* 6. Counterfactual Fragility Assessment */}
              {selectedPassport.fragility && (
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Layers size={14} style={{ color: 'var(--color-warning)' }} />
                      Counterfactual Fragility & Replay Sensitivity
                    </div>
                    <span className="badge badge-unavailable">
                      {selectedPassport.fragility.status || 'UNTESTED'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                    {selectedPassport.fragility.reason ||
                      'Sensitivity testing evaluates whether this finding flips under hypothetical packet omission.'}
                  </div>
                  {selectedPassport.fragility.tested_scenarios && (
                    <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Tested Scenarios: {selectedPassport.fragility.tested_scenarios} | Min Pairs to Flip: {selectedPassport.fragility.minimum_tested_pairs_to_change ?? 'None observed'}
                    </div>
                  )}
                </div>
              )}

              {/* 7. Safe Human-Analyst Next Steps */}
              <div className="card" style={{ padding: '16px', background: 'var(--color-surface-hover)' }}>
                <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                  <div className="card-title" style={{ fontSize: '13px' }}>
                    <Shield size={14} style={{ color: 'var(--color-healthy)' }} />
                    Evidence-Supported Next Steps (Human Analyst Workflow)
                  </div>
                </div>
                <ol style={{ paddingLeft: '18px', fontSize: '12px', color: 'var(--color-text-secondary)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {(selectedPassport.recommended_steps || [
                    'Cross-reference source endpoint with authorized maintenance windows or vulnerability scanners.',
                    'Inspect destination port distribution to confirm horizontal sweep vs targeted service scan.',
                    'Verify capture quality indicators to confirm no hardware or driver dropped frames.',
                    'Run counterfactual replay in Replay Lab to assess detection sensitivity under packet loss.'
                  ]).map((step, idx) => (
                    <li key={idx} style={{ lineHeight: 1.45 }}>{step}</li>
                  ))}
                </ol>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default AlertsView
