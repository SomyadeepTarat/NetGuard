import React, { useEffect, useState } from 'react'
import {
  FlaskConical,
  Play,
  CheckCircle2,
  Clock,
  Info,
  History,
  AlertTriangle,
  RefreshCw,
  Sliders,
  ShieldCheck,
  Compass,
  Eye,
  Link2
} from 'lucide-react'
import type { PcapFileInfo, ReplayExperiment } from '../types'
import { api } from '../api'
import { PageHeader } from './PageHeader'
import { RobustnessAtlasTab } from './RobustnessAtlasTab'
import { NextObservationTab } from './NextObservationTab'
import { EvidenceLineageTab } from './EvidenceLineageTab'

export const ReplayLabView: React.FC = () => {
  const [activeSubView, setActiveSubView] = useState<'single' | 'atlas' | 'planner' | 'lineage'>('single')
  const [pcaps, setPcaps] = useState<PcapFileInfo[]>([])
  const [selectedPcap, setSelectedPcap] = useState('')
  const [lossMode, setLossMode] = useState<'random' | 'burst' | 'directional'>('random')
  const [dropRate, setDropRate] = useState(0.15)
  const [seed, setSeed] = useState(42)
  const [burstSize, setBurstSize] = useState(4)
  const [burstInterval, setBurstInterval] = useState(20)

  const [running, setRunning] = useState(false)
  const [activeExp, setActiveExp] = useState<ReplayExperiment | null>(null)
  const [pastExperiments, setPastExperiments] = useState<ReplayExperiment[]>([])

  const loadInitial = async () => {
    try {
      const pcapList = await api.getAvailablePcaps()
      setPcaps(pcapList)
      if (pcapList.length > 0 && !selectedPcap) {
        // Default to a SYN_FLOOD or PORT_SCAN demo pcap if present
        const defaultChoice =
          pcapList.find((p) => p.filename.includes('SYN_FLOOD')) ||
          pcapList.find((p) => p.filename.includes('PORT_SCAN')) ||
          pcapList[0]
        setSelectedPcap(defaultChoice.relative_path)
      }
      const exps = await api.listReplays()
      setPastExperiments(exps)
      if (exps.length > 0 && !activeExp) {
        setActiveExp(exps[0])
      }
    } catch (e) {
      console.error('Failed to initialize Replay Lab:', e)
    }
  }

  useEffect(() => {
    loadInitial()
  }, [])

  // Polling active experiment until completion
  useEffect(() => {
    if (!activeExp || activeExp.status !== 'running') return
    const timer = setInterval(async () => {
      try {
        const updated = await api.getReplay(activeExp.run_id)
        setActiveExp(updated)
        if (updated.status !== 'running') {
          setRunning(false)
          const exps = await api.listReplays()
          setPastExperiments(exps)
        }
      } catch (e) {
        console.error('Polling replay run status failed:', e)
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [activeExp?.status, activeExp?.run_id])

  const handleLaunch = async () => {
    if (!selectedPcap) return
    setRunning(true)
    try {
      const exp = await api.createReplay({
        pcap_path: selectedPcap,
        loss_mode: lossMode,
        drop_rate: dropRate,
        seed,
        burst_size: burstSize,
        burst_interval: burstInterval,
      })
      setActiveExp(exp)
    } catch (e: any) {
      alert(`Experiment launch failed: ${e.message}`)
      setRunning(false)
    }
  }

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'STABLE':
        return <span className="badge badge-healthy">STABLE</span>
      case 'SENSITIVE':
        return <span className="badge badge-degraded">SENSITIVE</span>
      case 'INCONCLUSIVE':
        return <span className="badge badge-unknown">INCONCLUSIVE</span>
      default:
        return <span className="badge badge-unavailable">{verdict}</span>
    }
  }

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Counterfactual Replay Lab"
        description="Perturbation analysis and evidence stability testing under controlled observation loss."
        icon={<FlaskConical size={20} />}
        badge={
          activeExp && activeExp.status === 'completed' ? (
            getVerdictBadge(activeExp.stability_verdict)
          ) : (
            <span className="badge badge-unavailable">OFFLINE LAB</span>
          )
        }
        actions={
          <button
            className="btn btn-secondary"
            onClick={loadInitial}
            disabled={running}
            title="Refresh replay runs"
          >
            <RefreshCw size={13} className={running ? 'animate-spin' : ''} />
            <span>Sync Runs</span>
          </button>
        }
      />

      {/* Evidence Resilience Studio Sub-Navigation */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        borderBottom: '1px solid var(--color-border)',
        paddingBottom: '14px',
        marginBottom: '20px'
      }}>
        <button
          type="button"
          onClick={() => setActiveSubView('single')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: 'var(--radius-md)',
            fontSize: '12.5px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubView === 'single' ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
            background: activeSubView === 'single' ? 'var(--color-accent)' : 'var(--color-surface)',
            color: activeSubView === 'single' ? '#ffffff' : 'var(--color-text-secondary)',
            transition: 'all 0.15s ease'
          }}
        >
          <FlaskConical size={14} /> Single Replay
        </button>

        <button
          type="button"
          onClick={() => setActiveSubView('atlas')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: 'var(--radius-md)',
            fontSize: '12.5px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubView === 'atlas' ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
            background: activeSubView === 'atlas' ? 'var(--color-accent)' : 'var(--color-surface)',
            color: activeSubView === 'atlas' ? '#ffffff' : 'var(--color-text-secondary)',
            transition: 'all 0.15s ease'
          }}
        >
          <Compass size={14} /> Robustness Atlas
        </button>

        <button
          type="button"
          onClick={() => setActiveSubView('planner')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: 'var(--radius-md)',
            fontSize: '12.5px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubView === 'planner' ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
            background: activeSubView === 'planner' ? 'var(--color-accent)' : 'var(--color-surface)',
            color: activeSubView === 'planner' ? '#ffffff' : 'var(--color-text-secondary)',
            transition: 'all 0.15s ease'
          }}
        >
          <Eye size={14} /> Next Observation
        </button>

        <button
          type="button"
          onClick={() => setActiveSubView('lineage')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: 'var(--radius-md)',
            fontSize: '12.5px',
            fontWeight: 600,
            cursor: 'pointer',
            border: activeSubView === 'lineage' ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
            background: activeSubView === 'lineage' ? 'var(--color-accent)' : 'var(--color-surface)',
            color: activeSubView === 'lineage' ? '#ffffff' : 'var(--color-text-secondary)',
            transition: 'all 0.15s ease'
          }}
        >
          <Link2 size={14} /> Evidence Lineage
        </button>
      </div>

      {activeSubView === 'single' && (
        <>
          {/* Prominent Scientific Honesty Banner */}
          <div className="callout callout-advisory" style={{ marginTop: 0, marginBottom: '20px' }}>
            <Info size={18} style={{ flexShrink: 0 }} />
            <div>
              <strong>OFFLINE SIMULATION — NO PACKETS TRANSMITTED.</strong> Counterfactual observation-loss sensitivity tests whether a detection finding remains stable when the same capture is reprocessed under hypothetical packet loss. Simulated loss does not establish actual live packet loss or causality.
            </div>
          </div>

          {/* Two-Column Lab Workspace */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'minmax(320px, 390px) minmax(0, 1fr)',
              gap: '22px',
              alignItems: 'start',
            }}
          >
        {/* Left Column: Experiment Setup & History */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Setup Card */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Sliders size={15} style={{ color: 'var(--color-accent)' }} />
                Configure Perturbation Scenario
              </div>
              <span className="badge badge-unavailable">Simulation</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* PCAP File Selection */}
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '11.5px',
                    fontWeight: 600,
                    color: 'var(--color-text-secondary)',
                    marginBottom: '6px',
                  }}
                >
                  Source PCAP Stream
                </label>
                <select
                  className="select-input"
                  style={{ width: '100%' }}
                  value={selectedPcap}
                  onChange={(e) => setSelectedPcap(e.target.value)}
                  disabled={running}
                >
                  {pcaps.map((p) => (
                    <option key={p.relative_path} value={p.relative_path}>
                      {p.filename} ({p.category}) - {(p.size_bytes / 1024).toFixed(1)} KB
                    </option>
                  ))}
                </select>
              </div>

              {/* Loss Profile Selection */}
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '11.5px',
                    fontWeight: 600,
                    color: 'var(--color-text-secondary)',
                    marginBottom: '6px',
                  }}
                >
                  Perturbation Loss Profile
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                  {[
                    { id: 'random', label: 'Random Packet Loss' },
                    { id: 'burst', label: 'Burst Packet Loss' },
                    { id: 'directional', label: 'Directional Loss' },
                  ].map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      className="btn btn-secondary"
                      style={{
                        padding: '6px 8px',
                        fontSize: '11px',
                        fontWeight: 600,
                        background: lossMode === m.id ? 'var(--color-accent)' : undefined,
                        borderColor: lossMode === m.id ? 'var(--color-accent)' : undefined,
                        color: lossMode === m.id ? '#ffffff' : undefined,
                        gridColumn: m.id === 'directional' ? 'span 2' : undefined,
                      }}
                      onClick={() => setLossMode(m.id as any)}
                      disabled={running}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Loss Rate Slider */}
              <div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '11.5px',
                    color: 'var(--color-text-secondary)',
                    marginBottom: '6px',
                  }}
                >
                  <span style={{ fontWeight: 600 }}>Injected Omission Rate</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--color-accent)' }}>
                    {(dropRate * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.05"
                  max="0.5"
                  step="0.05"
                  value={dropRate}
                  onChange={(e) => setDropRate(parseFloat(e.target.value))}
                  disabled={running}
                  style={{ width: '100%', accentColor: 'var(--color-accent)' }}
                />
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '10px',
                    color: 'var(--color-text-muted)',
                    fontFamily: 'var(--font-mono)',
                    marginTop: '2px',
                  }}
                >
                  <span>5% (mild)</span>
                  <span>25% (moderate)</span>
                  <span>50% (severe)</span>
                </div>
              </div>

              {/* RNG Seed & Burst Parameters */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '11px',
                      color: 'var(--color-text-secondary)',
                      marginBottom: '4px',
                    }}
                  >
                    RNG Seed
                  </label>
                  <input
                    type="number"
                    className="input-text"
                    style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                    value={seed}
                    onChange={(e) => setSeed(parseInt(e.target.value, 10) || 0)}
                    disabled={running}
                  />
                </div>

                {lossMode === 'burst' ? (
                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '11px',
                        color: 'var(--color-text-secondary)',
                        marginBottom: '4px',
                      }}
                    >
                      Burst Size (pkts)
                    </label>
                    <input
                      type="number"
                      className="input-text"
                      style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                      value={burstSize}
                      onChange={(e) => setBurstSize(parseInt(e.target.value, 10) || 1)}
                      disabled={running}
                    />
                  </div>
                ) : (
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      fontSize: '11px',
                      color: 'var(--color-text-muted)',
                      padding: '4px 0',
                    }}
                  >
                    Deterministic seed ensures reproducibility.
                  </div>
                )}
              </div>

              {lossMode === 'burst' && (
                <div>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '11px',
                      color: 'var(--color-text-secondary)',
                      marginBottom: '4px',
                    }}
                  >
                    Burst Interval (packets between drops)
                  </label>
                  <input
                    type="number"
                    className="input-text"
                    style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
                    value={burstInterval}
                    onChange={(e) => setBurstInterval(parseInt(e.target.value, 10) || 10)}
                    disabled={running}
                  />
                </div>
              )}

              {/* Action Button */}
              <button
                className="btn btn-primary"
                style={{ width: '100%', padding: '9px 16px', marginTop: '4px' }}
                onClick={handleLaunch}
                disabled={running || !selectedPcap}
              >
                {running ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    <span>Reprocessing PCAP Through Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Play size={14} />
                    <span>Run Counterfactual Verification</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Past Experiments History */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div
              style={{
                padding: '12px 18px',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div className="card-title" style={{ fontSize: '13px' }}>
                <History size={14} style={{ color: 'var(--color-text-secondary)' }} />
                Experiment History
              </div>
              <span className="badge badge-unavailable">{pastExperiments.length} Runs</span>
            </div>

            {pastExperiments.length === 0 ? (
              <div style={{ padding: '20px', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '12px' }}>
                No prior replay experiments in this session.
              </div>
            ) : (
              <div style={{ maxHeight: '240px', overflowY: 'auto' }}>
                {pastExperiments.map((exp) => {
                  const isSelected = activeExp?.run_id === exp.run_id
                  return (
                    <div
                      key={exp.run_id}
                      onClick={() => setActiveExp(exp)}
                      style={{
                        padding: '10px 16px',
                        borderBottom: '1px solid var(--color-border-subtle)',
                        background: isSelected ? 'var(--color-accent-subtle)' : 'transparent',
                        cursor: 'pointer',
                        transition: 'background 0.1s ease',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--color-text-primary)' }}>
                          {exp.pcap_name}
                        </div>
                        <div
                          style={{
                            fontSize: '10.5px',
                            color: 'var(--color-text-muted)',
                            fontFamily: 'var(--font-mono)',
                            marginTop: '2px',
                          }}
                        >
                          {exp.loss_mode} ({(exp.drop_rate * 100).toFixed(0)}% drop)
                        </div>
                      </div>
                      <div>{getVerdictBadge(exp.stability_verdict)}</div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Comparative Findings & Invariance Verdict */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Active Experiment Report Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title">
                  <CheckCircle2 size={16} style={{ color: 'var(--color-accent)' }} />
                  Verification Findings: {activeExp?.pcap_name || 'No Experiment Active'}
                </div>
                <div className="card-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {activeExp ? `Run ID: ${activeExp.run_id} | Status: ${activeExp.status.toUpperCase()}` : 'Configure and launch a scenario on the left.'}
                </div>
              </div>
              {activeExp && getVerdictBadge(activeExp.stability_verdict)}
            </div>

            {/* Content for Running State */}
            {activeExp?.status === 'running' ? (
              <div style={{ textAlign: 'center', padding: '60px 20px' }}>
                <Clock size={36} className="animate-spin" style={{ margin: '0 auto 16px', color: 'var(--color-accent)' }} />
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  Reprocessing Stream Under Packet Omission...
                </h3>
                <p style={{ color: 'var(--color-text-secondary)', fontSize: '12.5px', maxWidth: '420px', margin: '0 auto' }}>
                  Simulating {(activeExp.drop_rate * 100).toFixed(0)}% {activeExp.loss_mode} loss on {activeExp.pcap_name}. Measuring feature stability and prediction invariance.
                </p>
              </div>
            ) : activeExp?.status === 'completed' ? (
              /* Completed Experiment Results */
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Stability Verdict Banner */}
                <div
                  className={`callout ${
                    activeExp.stability_verdict === 'STABLE'
                      ? 'callout-healthy'
                      : activeExp.stability_verdict === 'SENSITIVE'
                      ? 'callout-advisory'
                      : 'callout-info'
                  }`}
                  style={{ marginTop: 0, marginBottom: 0 }}
                >
                  {activeExp.stability_verdict === 'STABLE' ? (
                    <ShieldCheck size={20} style={{ flexShrink: 0, color: 'var(--color-healthy)' }} />
                  ) : activeExp.stability_verdict === 'SENSITIVE' ? (
                    <AlertTriangle size={20} style={{ flexShrink: 0, color: 'var(--color-warning)' }} />
                  ) : (
                    <Info size={20} style={{ flexShrink: 0 }} />
                  )}
                  <div>
                    {activeExp.stability_verdict === 'STABLE' && (
                      <div>
                        <strong>STABLE — DETECTION FINDINGS INVARIANT UNDER PACKET LOSS.</strong>
                        <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--color-text-secondary)' }}>
                          The detection classifications remained unchanged between the full capture and the reprocessed stream with {(activeExp.drop_rate * 100).toFixed(0)}% omitted packets. Evidence demonstrates robustness to capture loss.
                        </div>
                      </div>
                    )}
                    {activeExp.stability_verdict === 'SENSITIVE' && (
                      <div>
                        <strong>SENSITIVE — EVIDENCE FRAGILE TO OBSERVATION LOSS.</strong>
                        <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--color-text-secondary)' }}>
                          Simulated packet omission caused {activeExp.comparison.decision_shifts} classification shifts across observation windows. The finding may degrade into false negatives if network packets are dropped at capture.
                        </div>
                      </div>
                    )}
                    {activeExp.stability_verdict === 'INCONCLUSIVE' && (
                      <div>
                        <strong>INCONCLUSIVE — INSUFFICIENT SIGNAL WINDOWS.</strong>
                        <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--color-text-secondary)' }}>
                          The capture did not yield sufficient positive observation windows to establish statistically sound invariance conclusions.
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 3-Stat Metric Comparison Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                  <div className="stat-box" style={{ padding: '14px' }}>
                    <div className="stat-label">Baseline Windows</div>
                    <div className="stat-value" style={{ fontSize: '22px' }}>
                      {activeExp.comparison.baseline_suspicious_count ?? 0}
                    </div>
                    <div className="stat-sub">Flagged in full trace</div>
                  </div>

                  <div className="stat-box" style={{ padding: '14px' }}>
                    <div className="stat-label">Perturbed Windows</div>
                    <div className="stat-value" style={{ fontSize: '22px' }}>
                      {activeExp.comparison.perturbed_suspicious_count ?? 0}
                    </div>
                    <div className="stat-sub">Flagged after {(activeExp.drop_rate * 100).toFixed(0)}% loss</div>
                  </div>

                  <div className="stat-box" style={{ padding: '14px' }}>
                    <div className="stat-label">Decision Shifts</div>
                    <div
                      className="stat-value"
                      style={{
                        fontSize: '22px',
                        color:
                          (activeExp.comparison.decision_shifts ?? 0) > 0
                            ? 'var(--color-critical)'
                            : 'var(--color-healthy)',
                      }}
                    >
                      {activeExp.comparison.decision_shifts ?? 0}
                    </div>
                    <div className="stat-sub">Classification flips</div>
                  </div>
                </div>

                {/* Feature Shifts Aligned Table */}
                {activeExp.comparison.feature_shifts && (
                  <div>
                    <div
                      style={{
                        fontSize: '12.5px',
                        fontWeight: 600,
                        color: 'var(--color-text-primary)',
                        marginBottom: '8px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <span>Feature Value Deltas (Baseline vs Counterfactual)</span>
                      <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 400 }}>
                        Mean window feature differences
                      </span>
                    </div>

                    <div className="table-responsive" style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)' }}>
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Traffic Feature</th>
                            <th style={{ textAlign: 'right' }}>Baseline Value</th>
                            <th style={{ textAlign: 'right' }}>Perturbed Value</th>
                            <th style={{ textAlign: 'right' }}>Absolute Delta</th>
                            <th style={{ textAlign: 'right' }}>Shift (%)</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(activeExp.comparison.feature_shifts).map(([fKey, shift]) => (
                            <tr key={fKey}>
                              <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{fKey}</td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {shift.baseline.toFixed(4)}
                              </td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {shift.perturbed.toFixed(4)}
                              </td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {shift.difference > 0 ? `+${shift.difference.toFixed(4)}` : shift.difference.toFixed(4)}
                              </td>
                              <td
                                style={{
                                  textAlign: 'right',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: 600,
                                  color:
                                    shift.percentage_change !== null && Math.abs(shift.percentage_change) > 15
                                      ? 'var(--color-warning)'
                                      : 'var(--color-text-secondary)',
                                }}
                              >
                                {shift.percentage_change !== null
                                  ? `${shift.percentage_change > 0 ? '+' : ''}${shift.percentage_change.toFixed(1)}%`
                                  : 'N/A'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              /* Designed Initial State */
              <div style={{ textAlign: 'center', padding: '60px 20px' }}>
                <div
                  style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: '50%',
                    background: 'var(--color-surface-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    margin: '0 auto 16px',
                    color: 'var(--color-text-muted)',
                  }}
                >
                  <FlaskConical size={22} />
                </div>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
                  No Active Experiment Selected
                </h3>
                <p style={{ color: 'var(--color-text-secondary)', fontSize: '12.5px', maxWidth: '420px', margin: '0 auto 16px' }}>
                  Select an input PCAP capture and perturbation scenario on the left, then click <strong>Run Counterfactual Verification</strong> to test detection stability.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
      </>
      )}

      {activeSubView === 'atlas' && (
        <RobustnessAtlasTab
          pcaps={pcaps}
          selectedPcap={selectedPcap}
          onSelectPcap={setSelectedPcap}
        />
      )}

      {activeSubView === 'planner' && (
        <NextObservationTab
          sweeps={[]}
        />
      )}

      {activeSubView === 'lineage' && (
        <EvidenceLineageTab />
      )}
    </div>
  )
}

export default ReplayLabView
