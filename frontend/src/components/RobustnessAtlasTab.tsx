import React, { useState, useEffect } from 'react'
import {
  Compass,
  Play,
  XCircle,
  RefreshCw
} from 'lucide-react'
import type { PcapFileInfo, RobustnessSweepRun, ScenarioResultItem } from '../types'
import { api } from '../api'

interface Props {
  pcaps: PcapFileInfo[]
  selectedPcap: string
  onSelectPcap: (path: string) => void
}

export const RobustnessAtlasTab: React.FC<Props> = ({ pcaps, selectedPcap, onSelectPcap }) => {
  // Configuration
  const [lossModes, setLossModes] = useState<string[]>(['random', 'burst', 'directional'])
  const [dropRates, setDropRates] = useState<number[]>([0.05, 0.10, 0.20, 0.30, 0.50])
  const seeds = [11, 23, 37, 51, 79]
  const maxRuns = 30

  // Execution state
  const [activeSweep, setActiveSweep] = useState<RobustnessSweepRun | null>(null)
  const [recentSweeps, setRecentSweeps] = useState<RobustnessSweepRun[]>([])
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedScenario, setSelectedScenario] = useState<ScenarioResultItem | null>(null)

  // Load existing sweeps on mount
  useEffect(() => {
    loadSweeps()
  }, [])

  const loadSweeps = async () => {
    try {
      const runs = await api.listRobustnessSweeps()
      setRecentSweeps(runs)
      if (runs.length > 0 && !activeSweep) {
        setActiveSweep(runs[0])
      }
    } catch (e: any) {
      console.error('Failed to load robustness sweeps:', e)
    }
  }

  // Polling active sweep
  useEffect(() => {
    if (!activeSweep || (activeSweep.status !== 'queued' && activeSweep.status !== 'running')) return
    const timer = setInterval(async () => {
      try {
        const updated = await api.getRobustnessSweep(activeSweep.run_id)
        setActiveSweep(updated)
        if (updated.status !== 'queued' && updated.status !== 'running') {
          setRunning(false)
          loadSweeps()
        }
      } catch (e) {
        console.error('Polling sweep status failed:', e)
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [activeSweep?.status, activeSweep?.run_id])

  const handleLaunchSweep = async () => {
    if (!selectedPcap) {
      setError('Please select an authorized source PCAP capture first.')
      return
    }
    setError(null)
    setRunning(true)
    try {
      const run = await api.createRobustnessSweep({
        pcap_path: selectedPcap,
        loss_modes: lossModes,
        drop_rates: dropRates,
        seeds: seeds,
        max_runs: maxRuns,
      })
      setActiveSweep(run)
      loadSweeps()
    } catch (e: any) {
      setError(e.message || 'Failed to start robustness sweep')
      setRunning(false)
    }
  }

  const handleCancelSweep = async () => {
    if (!activeSweep) return
    try {
      await api.cancelRobustnessSweep(activeSweep.run_id)
      const updated = await api.getRobustnessSweep(activeSweep.run_id)
      setActiveSweep(updated)
      setRunning(false)
      loadSweeps()
    } catch (e: any) {
      alert(`Cancellation failed: ${e.message}`)
    }
  }

  const toggleMode = (mode: string) => {
    if (lossModes.includes(mode)) {
      if (lossModes.length === 1) return // Keep at least one
      setLossModes(lossModes.filter(m => m !== mode))
    } else {
      setLossModes([...lossModes, mode])
    }
  }

  const toggleRate = (rate: number) => {
    if (dropRates.includes(rate)) {
      if (dropRates.length === 1) return
      setDropRates(dropRates.filter(r => r !== rate))
    } else {
      setDropRates([...dropRates, rate].sort((a, b) => a - b))
    }
  }

  const getVerdictStyle = (verdict: string) => {
    switch (verdict) {
      case 'STABLE':
        return {
          bg: 'var(--color-healthy-bg)',
          border: 'var(--color-healthy-border)',
          text: 'var(--color-healthy)',
          title: 'STABLE (Bounded to Tested Space)',
          desc: 'No baseline threat decisions shifted across all executed observation impairment scenarios.',
        }
      case 'SENSITIVE':
        return {
          bg: 'var(--color-warning-bg)',
          border: 'var(--color-warning-border)',
          text: 'var(--color-warning)',
          title: 'SENSITIVE (Observation Fragility Detected)',
          desc: 'One or more controlled packet-loss scenarios changed baseline incident classifications.',
        }
      case 'INCONCLUSIVE':
      default:
        return {
          bg: 'var(--color-unknown-bg)',
          border: 'var(--color-unknown-border)',
          text: 'var(--color-unknown)',
          title: 'INCONCLUSIVE',
          desc: 'Insufficient baseline threat windows or low window coverage to establish a bounded verdict.',
        }
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '24px', alignItems: 'start' }}>
      {/* Left Configuration Column */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <Compass size={18} style={{ color: 'var(--color-accent)' }} />
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Atlas Sweep Matrix Builder
            </h3>
          </div>

          {error && (
            <div style={{
              background: 'var(--color-critical-bg)',
              border: '1px solid var(--color-critical-border)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 12px',
              color: 'var(--color-critical)',
              fontSize: '12px',
              marginBottom: '16px'
            }}>
              {error}
            </div>
          )}

          {/* PCAP Selector */}
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
              Authorized Source Capture
            </label>
            <select
              value={selectedPcap}
              onChange={(e) => onSelectPcap(e.target.value)}
              disabled={running}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-border)',
                background: 'var(--color-surface)',
                color: 'var(--color-text-primary)',
                fontSize: '13px',
                fontFamily: 'var(--font-mono)'
              }}
            >
              {pcaps.map((p) => (
                <option key={p.relative_path} value={p.relative_path}>
                  {p.filename} ({(p.size_bytes / 1024).toFixed(1)} KB)
                </option>
              ))}
            </select>
          </div>

          {/* Loss Profiles */}
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
              Scenario Families ({lossModes.length} selected)
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {[
                { id: 'random', label: 'Random Loss' },
                { id: 'burst', label: 'Burst Loss' },
                { id: 'directional', label: 'Directional' }
              ].map((m) => {
                const active = lossModes.includes(m.id)
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => toggleMode(m.id)}
                    disabled={running}
                    style={{
                      padding: '5px 10px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      fontWeight: 500,
                      cursor: running ? 'not-allowed' : 'pointer',
                      border: active ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                      background: active ? 'var(--color-accent-subtle)' : 'var(--color-surface)',
                      color: active ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                    }}
                  >
                    {m.label}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Nominal Loss Rates */}
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
              Impairment Levels
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {[0.05, 0.10, 0.20, 0.30, 0.50].map((r) => {
                const active = dropRates.includes(r)
                return (
                  <button
                    key={r}
                    type="button"
                    onClick={() => toggleRate(r)}
                    disabled={running}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '11px',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      cursor: running ? 'not-allowed' : 'pointer',
                      border: active ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                      background: active ? 'var(--color-accent-subtle)' : 'var(--color-surface)',
                      color: active ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                    }}
                  >
                    {Math.round(r * 100)}%
                  </button>
                )
              })}
            </div>
          </div>

          {/* Seed Ensemble Count */}
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '4px' }}>
              Deterministic Seeds Ensemble: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{seeds.join(', ')}</span>
            </label>
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
              Reproducible seeds generate identical perturbation patterns across runs.
            </span>
          </div>

          {/* Run Limit & Controls */}
          <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>Max Run Budget:</span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{maxRuns} runs</span>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              {!running ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleLaunchSweep}
                  style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                >
                  <Play size={15} /> Execute Sweep Matrix
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={handleCancelSweep}
                  style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '6px',
                    color: 'var(--color-critical)',
                    borderColor: 'var(--color-critical-border)'
                  }}
                >
                  <XCircle size={15} /> Cancel Sweep
                </button>
              )}
            </div>

            <p style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '12px', lineHeight: 1.4 }}>
              <strong>Advisory Simulation:</strong> Executed strictly in-memory over offline PCAP metadata. No network packets are transmitted.
            </p>
          </div>
        </div>

        {/* Sweep History */}
        <div className="card" style={{ padding: '16px' }}>
          <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '12px' }}>
            Recent Sweeps ({recentSweeps.length})
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '240px', overflowY: 'auto' }}>
            {recentSweeps.map((s) => (
              <div
                key={s.run_id}
                onClick={() => {
                  setActiveSweep(s)
                  setSelectedScenario(null)
                }}
                style={{
                  padding: '10px',
                  borderRadius: 'var(--radius-sm)',
                  border: activeSweep?.run_id === s.run_id ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                  background: activeSweep?.run_id === s.run_id ? 'var(--color-surface-hover)' : 'var(--color-surface)',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {s.pcap_name}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {s.completed_scenarios}/{s.total_scenarios} scenarios • {s.stability_verdict}
                  </div>
                </div>
                <span className={`badge ${s.status === 'completed' ? 'badge-healthy' : s.status === 'running' ? 'badge-degraded' : 'badge-unknown'}`}>
                  {s.status}
                </span>
              </div>
            ))}
            {recentSweeps.length === 0 && (
              <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', textAlign: 'center', padding: '16px' }}>
                No sweep runs recorded yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Results & Visualizations Column */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {activeSweep ? (
          <>
            {/* Header Status & Progress */}
            <div className="card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <h2 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      Robustness Sweep: {activeSweep.pcap_name}
                    </h2>
                    <span className="badge badge-subtle" style={{ fontFamily: 'var(--font-mono)' }}>
                      {activeSweep.run_id}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    SHA-256: {activeSweep.pcap_sha256 ? `${activeSweep.pcap_sha256.slice(0, 16)}...` : 'N/A'} • {activeSweep.total_scenarios} total configurations
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {activeSweep.status === 'running' && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--color-warning)' }}>
                      <RefreshCw size={13} className="spin" /> Executing {activeSweep.current_scenario_id || ''}...
                    </span>
                  )}
                  <span className={`badge ${activeSweep.status === 'completed' ? 'badge-healthy' : activeSweep.status === 'running' ? 'badge-degraded' : 'badge-unknown'}`}>
                    {activeSweep.status.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Progress Bar */}
              {activeSweep.total_scenarios > 0 && (
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>
                    <span>Scenario Execution Progress</span>
                    <span>{activeSweep.completed_scenarios} of {activeSweep.total_scenarios} ({Math.round((activeSweep.completed_scenarios / activeSweep.total_scenarios) * 100)}%)</span>
                  </div>
                  <div style={{ height: '6px', background: 'var(--color-surface-muted)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${(activeSweep.completed_scenarios / activeSweep.total_scenarios) * 100}%`,
                        height: '100%',
                        background: activeSweep.status === 'completed' ? 'var(--color-healthy)' : 'var(--color-accent)',
                        transition: 'width 0.3s ease'
                      }}
                    />
                  </div>
                </div>
              )}

              {/* Stability Verdict Banner */}
              {activeSweep.status === 'completed' && (
                (() => {
                  const vStyle = getVerdictStyle(activeSweep.stability_verdict)
                  return (
                    <div style={{
                      background: vStyle.bg,
                      border: `1px solid ${vStyle.border}`,
                      borderRadius: 'var(--radius-md)',
                      padding: '14px 18px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}>
                      <div>
                        <div style={{ fontSize: '14px', fontWeight: 700, color: vStyle.text, marginBottom: '2px' }}>
                          {vStyle.title}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                          {vStyle.desc}
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Alert Retention</div>
                        <div style={{ fontSize: '20px', fontWeight: 700, color: vStyle.text, fontFamily: 'var(--font-mono)' }}>
                          {activeSweep.envelope?.mean_alert_retention_rate !== undefined
                            ? `${Math.round(activeSweep.envelope.mean_alert_retention_rate * 100)}%`
                            : 'N/A'}
                        </div>
                      </div>
                    </div>
                  )
                })()
              )}
            </div>

            {/* Robustness Atlas Matrix Heatmap/Table */}
            {activeSweep.atlas_matrix?.cells && activeSweep.atlas_matrix.cells.length > 0 && (
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Observation Robustness Matrix (Profile × Nominal Impairment)
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Aggregated across deterministic seed ensembles
                  </span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  <table className="table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Loss Profile</th>
                        <th>Nominal Rate</th>
                        <th style={{ textAlign: 'right' }}>Evaluated Runs</th>
                        <th style={{ textAlign: 'right' }}>Realized Loss (Mean)</th>
                        <th style={{ textAlign: 'right' }}>Alert Retention</th>
                        <th style={{ textAlign: 'right' }}>Decision Shifts</th>
                        <th>Stability Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeSweep.atlas_matrix.cells.map((cell, idx) => (
                        <tr key={idx}>
                          <td style={{ fontWeight: 600, textTransform: 'capitalize' }}>{cell.loss_mode}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{cell.nominal_rate}</td>
                          <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{cell.runs_count}</td>
                          <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                            {(cell.avg_realized_omission * 100).toFixed(1)}%
                          </td>
                          <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                            {(cell.avg_alert_retention * 100).toFixed(1)}%
                          </td>
                          <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: cell.total_decision_shifts > 0 ? 'var(--color-warning)' : 'inherit' }}>
                            {cell.total_decision_shifts}
                          </td>
                          <td>
                            <span className={`badge ${cell.is_stable ? 'badge-healthy' : 'badge-degraded'}`}>
                              {cell.is_stable ? 'STABLE' : 'SENSITIVE'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Per-Scenario Results Table */}
            {activeSweep.scenario_results && activeSweep.scenario_results.length > 0 && (
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Evaluated Scenario Catalog ({activeSweep.scenario_results.length} runs)
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Click any scenario to inspect window coverage & feature drift
                  </span>
                </div>

                <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
                  <table className="table" style={{ width: '100%' }}>
                    <thead>
                      <tr>
                        <th>Scenario Identifier</th>
                        <th>Seed</th>
                        <th style={{ textAlign: 'right' }}>Config vs Realized</th>
                        <th style={{ textAlign: 'right' }}>Packets (Ret/Omit)</th>
                        <th style={{ textAlign: 'right' }}>Window Coverage</th>
                        <th style={{ textAlign: 'right' }}>Alert Retention</th>
                        <th style={{ textAlign: 'right' }}>Decision Shifts</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeSweep.scenario_results.map((sc) => {
                        const isSelected = selectedScenario?.scenario_id === sc.scenario_id
                        return (
                          <tr
                            key={sc.scenario_id}
                            onClick={() => setSelectedScenario(sc)}
                            style={{
                              cursor: 'pointer',
                              background: isSelected ? 'var(--color-surface-hover)' : 'inherit'
                            }}
                          >
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', fontWeight: isSelected ? 600 : 400 }}>
                              {sc.scenario_id}
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{sc.seed}</td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                              {(sc.nominal_drop_rate * 100).toFixed(0)}% → {(sc.realized_omission_rate * 100).toFixed(1)}%
                            </td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
                              {sc.retained_packets} / {sc.omitted_packets}
                            </td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                              {(sc.window_alignment_coverage * 100).toFixed(1)}%
                            </td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                              {(sc.alert_retention_rate * 100).toFixed(0)}%
                            </td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', color: sc.decision_shifts > 0 ? 'var(--color-warning)' : 'inherit' }}>
                              {sc.decision_shifts}
                            </td>
                            <td>
                              <span className={`badge ${sc.status === 'completed' ? 'badge-healthy' : 'badge-degraded'}`}>
                                {sc.status}
                              </span>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Selected Scenario Feature Shift Detail */}
            {selectedScenario && selectedScenario.mean_feature_shifts && (
              <div className="card" style={{ padding: '20px', border: '1px solid var(--color-accent-border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      Feature Drift Breakdown: {selectedScenario.scenario_id}
                    </h3>
                    <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                      Alignment Coverage: {(selectedScenario.window_alignment_coverage * 100).toFixed(1)}% ({selectedScenario.matched_windows} matched windows)
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn btn-outline"
                    style={{ fontSize: '11px', padding: '3px 8px' }}
                    onClick={() => setSelectedScenario(null)}
                  >
                    Close
                  </button>
                </div>

                <table className="table" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Feature Name</th>
                      <th style={{ textAlign: 'right' }}>Baseline Mean</th>
                      <th style={{ textAlign: 'right' }}>Perturbed Mean</th>
                      <th style={{ textAlign: 'right' }}>Absolute Delta</th>
                      <th style={{ textAlign: 'right' }}>% Shift</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(selectedScenario.mean_feature_shifts).map(([fKey, shift]) => (
                      <tr key={fKey}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{fKey}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{shift.baseline.toFixed(4)}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{shift.perturbed.toFixed(4)}</td>
                        <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                          {shift.difference > 0 ? `+${shift.difference.toFixed(4)}` : shift.difference.toFixed(4)}
                        </td>
                        <td style={{
                          textAlign: 'right',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 600,
                          color: shift.percentage_change !== null && Math.abs(shift.percentage_change) > 15 ? 'var(--color-warning)' : 'inherit'
                        }}>
                          {shift.percentage_change !== null ? `${shift.percentage_change > 0 ? '+' : ''}${shift.percentage_change.toFixed(1)}%` : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        ) : (
          <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
            <Compass size={36} style={{ color: 'var(--color-text-muted)', margin: '0 auto 16px' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '8px' }}>
              No Robustness Sweep Selected
            </h3>
            <p style={{ color: 'var(--color-text-secondary)', fontSize: '13px', maxWidth: '440px', margin: '0 auto 16px' }}>
              Select a source PCAP capture and configure the perturbation matrix on the left, then click <strong>Execute Sweep Matrix</strong> to generate a comprehensive Observation Robustness Atlas.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
