import React, { useEffect, useState } from 'react'
import { Download, Shield, Server } from 'lucide-react'
import { api } from '../api'

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<any>(null)
  const [redactIps, setRedactIps] = useState(false)

  useEffect(() => {
    api.getSettings().then(setSettings).catch(console.error)
  }, [])

  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '18px' }}>
        {/* Reports & Exports */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Download size={16} style={{ color: 'var(--accent-cyan)' }} />
              Export Observability Reports
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Export stored Evidence Passports and incident metadata for offline compliance, SIEM integration, or academic analysis.
            </p>

            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', cursor: 'pointer', color: 'var(--text-primary)' }}>
              <input
                type="checkbox"
                checked={redactIps}
                onChange={(e) => setRedactIps(e.target.checked)}
              />
              Pseudonymize IP Addresses (Mask last octets)
            </label>

            <div style={{ display: 'flex', gap: '10px' }}>
              <a
                href={`/api/alerts/export/json?redact_ips=${redactIps}`}
                download
                className="btn btn-primary"
                style={{ flex: 1 }}
              >
                <Download size={14} /> Download JSON
              </a>
              <a
                href={`/api/alerts/export/csv?redact_ips=${redactIps}`}
                download
                className="btn btn-secondary"
                style={{ flex: 1 }}
              >
                <Download size={14} /> Download CSV
              </a>
            </div>
          </div>
        </div>

        {/* Runtime Configuration & Security Posture */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Server size={16} style={{ color: 'var(--accent-cyan)' }} />
              Security Posture & Configuration
            </div>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <tbody>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Binding Address</td>
                  <td>{settings?.host_binding || '127.0.0.1'} (Loopback Only)</td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>HTTP Port</td>
                  <td>{settings?.port || 8000}</td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Active Ingestion Mode</td>
                  <td>
                    <span className="badge badge-unavailable">{settings?.mode || 'DEMO'}</span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Model Artifact Loaded</td>
                  <td>
                    <span className={`badge ${settings?.model_loaded ? 'badge-healthy' : 'badge-unknown'}`}>
                      {settings?.model_loaded ? 'LOADED' : 'RULE-ONLY FALLBACK'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Anomaly Baseline Ready</td>
                  <td>
                    <span className={`badge ${settings?.anomaly_baseline_ready ? 'badge-healthy' : 'badge-unknown'}`}>
                      {settings?.anomaly_baseline_ready ? 'READY' : 'WARMING UP'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: 'var(--text-secondary)' }}>Payload Retention Policy</td>
                  <td>Metadata Only (Payloads Never Stored)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Ethics & Read-Only Advisory Notice */}
      <div className="card" style={{ marginTop: '18px' }}>
        <div className="card-header">
          <div className="card-title">
            <Shield size={16} style={{ color: 'var(--accent-emerald)' }} />
            Academic Ethics & Defensive Scope Disclosures
          </div>
        </div>
        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          <p style={{ marginBottom: '8px' }}>
            NetGuard is an <strong>advisory, passive network observatory</strong>. It does not inject attack packets, transmit exploits, alter firewall configurations, or execute automated IP blocking.
          </p>
          <p style={{ marginBottom: '8px' }}>
            Live capture is restricted exclusively to network interfaces the operator is explicitly authorized to monitor. In demo mode, all packet traces are synthesized deterministically on the local machine and never transmitted over external network boundaries.
          </p>
          <p>
            Classifier confidence scores represent uncalibrated random forest outputs, not absolute probabilities of real-world compromise. Suspicious findings require human analyst verification before remediation actions are initiated.
          </p>
        </div>
      </div>
    </div>
  )
}
