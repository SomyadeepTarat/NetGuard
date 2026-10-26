import React, { useState } from 'react'
import {
  Play,
  Square,
  RefreshCw,
  AlertTriangle,
  Menu,
  ShieldCheck,
  CheckCircle2,
  X
} from 'lucide-react'
import type { OverviewData } from '../types'
import { api } from '../api'

interface HeaderProps {
  overview: OverviewData | null
  loading: boolean
  onRefresh: () => void
  onToggleMobileNav?: () => void
}

export const Header: React.FC<HeaderProps> = ({
  overview,
  loading,
  onRefresh,
  onToggleMobileNav,
}) => {
  const [showModal, setShowModal] = useState(false)
  const [startMode, setStartMode] = useState<'auto' | 'demo' | 'live' | 'pcap'>('auto')
  const [ifaceInput, setIfaceInput] = useState('')
  const [pcapInput, setPcapInput] = useState('')
  const [filterInput, setFilterInput] = useState('')
  const [actionLoading, setActionLoading] = useState(false)

  const isCapturing = overview?.status === 'CAPTURING'
  const mode = overview?.mode || 'DEMO'
  const quality = overview?.capture_quality?.overall_status || 'UNKNOWN'

  const handleStart = async () => {
    setActionLoading(true)
    try {
      await api.startCapture(
        startMode,
        startMode === 'live' || startMode === 'auto' ? ifaceInput || undefined : undefined,
        startMode === 'pcap' || startMode === 'auto' ? pcapInput || undefined : undefined,
        filterInput || undefined
      )
      setShowModal(false)
      onRefresh()
    } catch (e: any) {
      alert(`Capture initialization failed: ${e.message}`)
    } finally {
      setActionLoading(false)
    }
  }

  const handleStop = async () => {
    setActionLoading(true)
    try {
      await api.stopCapture()
      onRefresh()
    } catch (e: any) {
      alert(`Capture stop failed: ${e.message}`)
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <>
      <header className="workstation-header">
        <div className="header-left">
          {onToggleMobileNav && (
            <button
              className="header-menu-btn"
              onClick={onToggleMobileNav}
              aria-label="Toggle navigation drawer"
            >
              <Menu size={18} />
            </button>
          )}

          {/* Persistent Ingestion Mode Badge */}
          <div
            className={`header-mode-tag ${
              mode === 'DEMO'
                ? 'mode-tag-demo'
                : mode === 'LIVE'
                ? 'mode-tag-live'
                : 'mode-tag-pcap'
            }`}
          >
            <span
              className={`status-dot ${isCapturing ? 'active' : 'stopped'}`}
            />
            <span>
              {mode === 'DEMO' && 'DEMO / SYNTHETIC (OFFLINE)'}
              {mode === 'LIVE' && 'LIVE CAPTURE (AUTHORIZED)'}
              {mode === 'PCAP' && 'PCAP REPLAY'}
            </span>
          </div>

          {/* Active Interface or Ingestion Source */}
          <div className="header-source-info">
            <span style={{ color: 'var(--color-text-muted)' }}>src:</span>
            <span style={{ fontWeight: 600 }}>{overview?.interface || 'idle'}</span>
          </div>

          {/* Capture Fidelity Indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11px',
              color: 'var(--color-text-secondary)',
            }}
          >
            <ShieldCheck
              size={14}
              style={{
                color:
                  quality === 'HEALTHY'
                    ? 'var(--color-healthy)'
                    : quality === 'DEGRADED'
                    ? 'var(--color-warning)'
                    : 'var(--color-unknown)',
              }}
            />
            <span>Quality:</span>
            <span
              className={`badge ${
                quality === 'HEALTHY'
                  ? 'badge-healthy'
                  : quality === 'DEGRADED'
                  ? 'badge-degraded'
                  : 'badge-unknown'
              }`}
            >
              {quality}
            </span>
          </div>
        </div>

        <div className="header-right">
          {isCapturing ? (
            <button
              className="btn btn-danger"
              onClick={handleStop}
              disabled={actionLoading}
              title="Halt current ingestion session"
            >
              <Square size={13} fill="currentColor" />
              <span>Stop Capture</span>
            </button>
          ) : (
            <button
              className="btn btn-primary"
              onClick={() => setShowModal(true)}
              disabled={actionLoading}
              title="Configure and launch a capture session"
            >
              <Play size={13} fill="currentColor" />
              <span>Start Ingestion</span>
            </button>
          )}

          <button
            className="btn btn-secondary"
            onClick={onRefresh}
            disabled={loading}
            title="Refresh active metrics telemetry"
            aria-label="Refresh telemetry"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </header>

      {/* Start Ingestion Modal */}
      {showModal && (
        <div className="modal-backdrop" onClick={() => setShowModal(false)}>
          <div
            className="modal-card"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="modal-title"
          >
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: 'var(--color-surface-hover)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Play size={16} style={{ color: 'var(--color-accent)' }} />
                <h2 id="modal-title" style={{ fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  Initialize Ingestion Pipeline
                </h2>
              </div>
              <button
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--color-text-muted)',
                  display: 'flex',
                }}
                onClick={() => setShowModal(false)}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '6px' }}>
                  Ingestion Mode
                </label>
                <select
                  className="select-input"
                  style={{ width: '100%', padding: '8px 12px' }}
                  value={startMode}
                  onChange={(e) => setStartMode(e.target.value as any)}
                >
                  <option value="auto">Automatic: actual network → dataset fallback</option>
                  <option value="demo">Deterministic Synthetic Demo (Offline Simulation)</option>
                  <option value="live">Live Network Interface (Authorized Promiscuous Monitoring)</option>
                  <option value="pcap">Offline PCAP Replay</option>
                </select>
              </div>

              {startMode === 'demo' && (
                <div className="callout callout-info" style={{ margin: 0 }}>
                  <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
                  <div>
                    <strong>Continuous Safe Simulation:</strong> Ingests bounded multi-protocol traffic with verified benign sessions, port sweeps, and floods. Runs entirely in user-space without raw socket privileges.
                  </div>
                </div>
              )}

              {startMode === 'auto' && (
                <div className="callout callout-info" style={{ margin: 0 }}>
                  Uses an active local adapter when the capture driver is ready. Falls back to your PCAP dataset and retries live capture every 5 seconds. Without a dataset, synthetic fixtures are clearly labeled.
                </div>
              )}

              {(startMode === 'live' || startMode === 'auto') && (
                <>
                  <div>
                    <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '4px' }}>
                      Interface Identifier (Optional)
                    </label>
                    <input
                      type="text"
                      className="input-text"
                      style={{ width: '100%' }}
                      placeholder="e.g. eth0, Wi-Fi, or leave empty for default route"
                      value={ifaceInput}
                      onChange={(e) => setIfaceInput(e.target.value)}
                    />
                  </div>
                  <div className="callout callout-advisory" style={{ margin: 0 }}>
                    <AlertTriangle size={16} style={{ flexShrink: 0 }} />
                    <div>
                      <strong>Administrative Privilege Requirement:</strong> Live capture requires packet capture drivers (Npcap on Windows or CAP_NET_RAW / root on Linux). NetGuard passively observes packet headers without transmission.
                    </div>
                  </div>
                </>
              )}

              {(startMode === 'pcap' || startMode === 'auto') && (
                <div>
                  <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '4px' }}>
                    Relative PCAP Capture Path
                  </label>
                  <input
                    type="text"
                    className="input-text font-mono"
                    style={{ width: '100%' }}
                    placeholder="artifacts/demo/test-PORT_SCAN-0.pcap"
                    value={pcapInput}
                    onChange={(e) => setPcapInput(e.target.value)}
                  />
                </div>
              )}

              <div>
                <label style={{ display: 'block', fontSize: '11.5px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '4px' }}>
                  BPF Kernel Filter Expression (Optional)
                </label>
                <input
                  type="text"
                  className="input-text font-mono"
                  style={{ width: '100%' }}
                  placeholder="e.g. tcp and port 80 or udp port 53"
                  value={filterInput}
                  onChange={(e) => setFilterInput(e.target.value)}
                />
              </div>

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: '10px',
                  paddingTop: '12px',
                  borderTop: '1px solid var(--color-border-subtle)',
                }}
              >
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleStart}
                  disabled={actionLoading}
                >
                  {actionLoading ? 'Initializing...' : 'Launch Ingestion'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
