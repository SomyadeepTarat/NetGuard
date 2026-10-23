import React, { useEffect, useState } from 'react'
import {
  Download,
  Shield,
  Server,
  Lock,
  FileText,
  RefreshCw,
  EyeOff,
  Settings as SettingsIcon
} from 'lucide-react'
import { api } from '../api'
import { PageHeader } from './PageHeader'

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<any>(null)
  const [redactIps, setRedactIps] = useState(false)
  const [loading, setLoading] = useState(true)

  const fetchSettings = () => {
    setLoading(true)
    api.getSettings()
      .then(setSettings)
      .catch((e) => console.error('Failed to load settings:', e))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchSettings()
  }, [])

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Reports & Workstation Settings"
        description="Incident export generation, IP pseudonymization options, and runtime security posture."
        icon={<SettingsIcon size={20} />}
        badge={
          <span className="badge badge-healthy">
            <Lock size={11} /> Loopback Binding (127.0.0.1:{settings?.port || 8000})
          </span>
        }
        actions={
          <button
            className="btn btn-secondary"
            onClick={fetchSettings}
            disabled={loading}
            title="Refresh runtime settings"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Main Grid Layout */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        {/* Reports & Exports Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Download size={16} style={{ color: 'var(--color-accent)' }} />
              Export Observability Incident Reports
            </div>
            <span className="badge badge-unavailable">Audit Ready</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', flex: 1 }}>
            <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              Export stored Evidence Passports and incident metadata for external compliance documentation, SIEM ingestion, or academic research artifacts.
            </p>

            {/* Pseudonymization Box */}
            <div
              style={{
                padding: '14px 16px',
                background: 'var(--color-surface-hover)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  color: 'var(--color-text-primary)',
                  userSelect: 'none',
                }}
              >
                <input
                  type="checkbox"
                  checked={redactIps}
                  onChange={(e) => setRedactIps(e.target.checked)}
                  style={{ width: '16px', height: '16px', accentColor: 'var(--color-accent)' }}
                />
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <EyeOff size={15} style={{ color: redactIps ? 'var(--color-accent)' : 'var(--color-text-muted)' }} />
                  Pseudonymize IP Addresses (Safe for Public Presentation)
                </span>
              </label>
              <div
                style={{
                  fontSize: '11.5px',
                  color: 'var(--color-text-secondary)',
                  marginTop: '8px',
                  paddingLeft: '26px',
                  lineHeight: 1.45,
                }}
              >
                When active, host octets in exported JSON and CSV files are pseudonymized to prevent revealing private workstation or lab network addresses during demonstrations.
              </div>
            </div>

            {/* Export Actions */}
            <div style={{ marginTop: 'auto', paddingTop: '10px', display: 'flex', gap: '12px' }}>
              <a
                href={`/api/alerts/export/json?redact_ips=${redactIps}`}
                download
                className="btn btn-primary"
                style={{ flex: 1, padding: '10px 14px' }}
              >
                <Download size={14} /> Download JSON Export
              </a>
              <a
                href={`/api/alerts/export/csv?redact_ips=${redactIps}`}
                download
                className="btn btn-secondary"
                style={{ flex: 1, padding: '10px 14px' }}
              >
                <FileText size={14} /> Download CSV Export
              </a>
            </div>
          </div>
        </div>

        {/* Runtime Configuration & Security Posture Card */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div className="card-title">
              <Server size={16} style={{ color: 'var(--color-accent)' }} />
              Runtime Security Posture & Binding
            </div>
            <span className="badge badge-healthy">Passive Only</span>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)', width: '40%' }}>Platform Identity</td>
                  <td style={{ fontWeight: 600 }}>{settings?.app_name || 'NetGuard Observatory'}</td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Software Version</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{settings?.version || '1.0.0-evidence-aware'}</td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Host Binding Address</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {settings?.host_binding || '127.0.0.1'} (Strict Loopback Only)
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>HTTP Listening Port</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{settings?.port || 8000}</td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Active Ingestion Mode</td>
                  <td>
                    <span className="badge badge-unavailable">{settings?.mode || 'DEMO'}</span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Capture Interface</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {settings?.interface || 'Synthetic Generator'}
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>ML Classifier Artifact</td>
                  <td>
                    <span
                      className={`badge ${
                        settings?.model_loaded ? 'badge-healthy' : 'badge-unknown'
                      }`}
                    >
                      {settings?.model_loaded ? 'RANDOM FOREST LOADED' : 'RULE-ONLY FALLBACK'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Anomaly Baseline</td>
                  <td>
                    <span
                      className={`badge ${
                        settings?.anomaly_baseline_ready ? 'badge-healthy' : 'badge-unknown'
                      }`}
                    >
                      {settings?.anomaly_baseline_ready ? 'CALIBRATED & READY' : 'WARMING UP'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--color-text-secondary)' }}>Payload Retention Policy</td>
                  <td style={{ fontSize: '12px' }}>
                    {settings?.retention_policy || 'Metadata only (payloads never stored)'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Academic Ethics & Defensive Scope Disclosures Card */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <Shield size={16} style={{ color: 'var(--color-healthy)' }} />
            Academic Ethics & Defensive Scope Disclosures
          </div>
          <span className="badge badge-unavailable">Ethics Statement</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          <div
            style={{
              padding: '14px',
              background: 'var(--color-surface-hover)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border-subtle)',
            }}
          >
            <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
              1. Non-Intrusive Passive Observation
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              NetGuard is an advisory, passive network observatory. It never injects attack packets, transmits exploit payloads, alters routing tables, or executes automated IP blocking.
            </div>
          </div>

          <div
            style={{
              padding: '14px',
              background: 'var(--color-surface-hover)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border-subtle)',
            }}
          >
            <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
              2. Interface Authorization & Containment
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              Live packet capture is restricted exclusively to interfaces the operator is authorized to monitor. In demo mode, all packet traces are synthesized locally and never transmitted across external network boundaries.
            </div>
          </div>

          <div
            style={{
              padding: '14px',
              background: 'var(--color-surface-hover)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--color-border-subtle)',
            }}
          >
            <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
              3. Human Analyst Verification Boundary
            </div>
            <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              Classifier confidence scores represent uncalibrated Random Forest tree votes, not absolute attack probabilities. Suspicious findings require human verification before remediation.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default SettingsView
