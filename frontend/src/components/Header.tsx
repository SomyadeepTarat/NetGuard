import React, { useState } from 'react'
import { Shield, Radio, Play, Square, RefreshCw, AlertTriangle } from 'lucide-react'
import type { OverviewData } from '../types'
import { api } from '../api'

interface HeaderProps {
  overview: OverviewData | null
  loading: boolean
  onRefresh: () => void
}

export const Header: React.FC<HeaderProps> = ({ overview, loading, onRefresh }) => {
  const [showModal, setShowModal] = useState(false)
  const [startMode, setStartMode] = useState<'demo' | 'live' | 'pcap'>('demo')
  const [ifaceInput, setIfaceInput] = useState('')
  const [pcapInput, setPcapInput] = useState('')
  const [filterInput, setFilterInput] = useState('')
  const [actionLoading, setActionLoading] = useState(false)

  const isCapturing = overview?.status === 'CAPTURING'
  const mode = overview?.mode || 'DEMO'

  const handleStart = async () => {
    setActionLoading(true)
    try {
      await api.startCapture(
        startMode,
        startMode === 'live' ? ifaceInput : undefined,
        startMode === 'pcap' ? pcapInput : undefined,
        filterInput || undefined
      )
      setShowModal(false)
      onRefresh()
    } catch (e: any) {
      alert(`Start failed: ${e.message}`)
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
      alert(`Stop failed: ${e.message}`)
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <>
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-logo">
            <Shield size={24} />
          </div>
          <div>
            <div className="brand-title">
              NETGUARD
              <span className="brand-subtitle">Threat Observatory</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Capture-Aware Incident Verification
            </div>
          </div>

          {/* Persistent Mode Label */}
          <div className={`mode-badge ${mode.toLowerCase()}`}>
            <Radio size={12} className={isCapturing ? 'animate-pulse' : ''} />
            {mode === 'DEMO' && 'DEMO / SYNTHETIC (OFFLINE)'}
            {mode === 'LIVE' && 'LIVE CAPTURE (AUTHORIZED)'}
            {mode === 'PCAP' && 'PCAP REPLAY'}
          </div>

          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            src: {overview?.interface || '-'}
          </div>
        </div>

        <div className="header-controls">
          {isCapturing ? (
            <button
              className="btn btn-danger"
              onClick={handleStop}
              disabled={actionLoading}
              title="Stop packet capture session"
            >
              <Square size={14} />
              Stop Capture
            </button>
          ) : (
            <button
              className="btn btn-primary"
              onClick={() => setShowModal(true)}
              disabled={actionLoading}
              title="Configure and start capture session"
            >
              <Play size={14} />
              Start Capture
            </button>
          )}

          <button
            className="btn btn-secondary"
            onClick={onRefresh}
            disabled={loading}
            title="Refresh current metrics snapshot"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </header>

      {/* Start Capture Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '480px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>
              Configure Ingestion Source
            </h3>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Capture Mode
              </label>
              <select
                className="select-input"
                style={{ width: '100%' }}
                value={startMode}
                onChange={(e) => setStartMode(e.target.value as any)}
              >
                <option value="demo">Deterministic Synthetic Demo (Safe Offline)</option>
                <option value="live">Live Network Interface (Authorized Monitoring)</option>
                <option value="pcap">Offline PCAP Replay</option>
              </select>
            </div>

            {startMode === 'demo' && (
              <div className="callout callout-info">
                Plays continuous locally generated demo sessions with benign downloads and attack patterns. No network privileges required.
              </div>
            )}

            {startMode === 'live' && (
              <>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Interface Name (optional, defaults to primary route)
                  </label>
                  <input
                    type="text"
                    className="input-text"
                    style={{ width: '100%' }}
                    placeholder="e.g. eth0, en0, or leave blank"
                    value={ifaceInput}
                    onChange={(e) => setIfaceInput(e.target.value)}
                  />
                </div>
                <div className="callout callout-advisory">
                  <AlertTriangle size={16} />
                  <div>
                    Live capture monitors network headers on the operator's machine. Requires elevated OS permissions (Npcap on Windows, root/sudo on Linux).
                  </div>
                </div>
              </>
            )}

            {startMode === 'pcap' && (
              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Relative PCAP Path
                </label>
                <input
                  type="text"
                  className="input-text"
                  style={{ width: '100%' }}
                  placeholder="artifacts/demo/test-PORT_SCAN-0.pcap"
                  value={pcapInput}
                  onChange={(e) => setPcapInput(e.target.value)}
                />
              </div>
            )}

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Optional BPF Filter
              </label>
              <input
                type="text"
                className="input-text"
                style={{ width: '100%' }}
                placeholder="e.g. tcp or udp port 53"
                value={filterInput}
                onChange={(e) => setFilterInput(e.target.value)}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button className="btn btn-secondary" onClick={() => setShowModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleStart} disabled={actionLoading}>
                {actionLoading ? 'Starting...' : 'Confirm & Ingest'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
