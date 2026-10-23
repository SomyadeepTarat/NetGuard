import React, { useEffect, useState } from 'react'
import {
  FlaskConical,
  Play,
  CheckCircle2,
  Clock,
  TrendingDown,
  Info,
  History
} from 'lucide-react'
import type { PcapFileInfo, ReplayExperiment } from '../types'
import { api } from '../api'

export const ReplayLabView: React.FC = () => {
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
        const defaultChoice = pcapList.find((p) => p.filename.includes('SYN_FLOOD')) || pcapList[0]
        setSelectedPcap(defaultChoice.relative_path)
      }
      const exps = await api.listReplays()
      setPastExperiments(exps)
      if (exps.length > 0 && !activeExp) {
        setActiveExp(exps[0])
      }
    } catch (e) {
      console.error(e)
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
        console.error(e)
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

  return (
    <div>
      {/* Prominent Honesty Banner */}
      <div className="callout callout-advisory" style={{ marginTop: 0, marginBottom: '16px' }}>
        <Info size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>OFFLINE SIMULATION — NO PACKETS TRANSMITTED.</strong> Counterfactual observation-loss sensitivity tests whether a detection finding remains stable when the same capture is reprocessed under hypothetical packet loss. Simulated loss does not establish actual live packet loss or causality.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '18px', marginBottom: '18px' }}>
        {/* Experiment Configuration Panel */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <FlaskConical size={16} style={{ color: 'var(--accent-amber)' }} />
              Configure Counterfactual Scenario
            </div>
            <span className="badge badge-unknown">LAB EXPERIMENT</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {/* Input PCAP */}
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Select Input PCAP
              </label>
              <select
                className="select-input"
                style={{ width: '100%' }}
                value={selectedPcap}
                onChange={(e) => setSelectedPcap(e.target.value)}
              >
                {pcaps.map((p) => (
                  <option key={p.relative_path} value={p.relative_path}>
                    {p.filename} ({p.category}) - {(p.size_bytes / 1024).toFixed(1)} KB
                  </option>
                ))}
              </select>
            </div>

            {/* Perturbation Mode */}
            <div>
              <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Perturbation Loss Profile
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                {[
                  { id: 'random', label: 'Random Packet Loss' },
                  { id: 'burst', label: 'Burst Packet Loss' },
                  { id: 'directional', label: 'Directional Loss' },
                ].map((m) => (
                  <button
                    key={m.id}
                    className="btn btn-secondary"
                    style={{
                      flex: 1,
                      fontSize: '11px',
                      background: lossMode === m.id ? 'var(--accent-amber-bg)' : undefined,
                      borderColor: lossMode === m.id ? 'var(--accent-amber-border)' : undefined,
                      color: lossMode === m.id ? 'var(--accent-amber)' : undefined,
                    }}
                    onClick={() => setLossMode(m.id as any)}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Loss Rate Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                <span>Injected Omission Rate</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)' }}>
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
                style={{ width: '100%', accentColor: 'var(--accent-amber)' }}
              />
            </div>

            {/* Seed & Burst Settings */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  RNG Seed (Deterministic)
                </label>
                <input
                  type="number"
                  className="input-text"
                  style={{ width: '100%' }}
                  value={seed}
                  onChange={(e) => setSeed(parseInt(e.target.value) || 0)}
                />
              </div>

              {lossMode === 'burst' ? (
                <div>
                  <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Burst Size (pkts)
                  </label>
                  <input
                    type="number"
                    className="input-text"
                    style={{ width: '100%' }}
                    value={burstSize}
                    onChange={(e) => setBurstSize(parseInt(e.target.value) || 1)}
                  />
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'flex-end', fontSize: '11px', color: 'var(--text-muted)' }}>
                  Reproducible seed guarantees fixed perturbation.
                </div>
              )}
            </div>

            {lossMode === 'burst' && (
              <div>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Burst Interval (pkts between bursts)
                </label>
                <input
                  type="number"
                  className="input-text"
                  style={{ width: '100%' }}
                  value={burstInterval}
                  onChange={(e) => setBurstInterval(parseInt(e.target.value) || 10)}
                />
              </div>
            )}

            {/* Launch Button */}
            <button
              className="btn btn-primary"
              style={{ background: 'var(--accent-amber)', color: '#041017', marginTop: '6px' }}
              onClick={handleLaunch}
              disabled={running || !selectedPcap}
            >
              <Play size={14} />
              {running ? 'Reprocessing PCAP Through Detector...' : 'Run Counterfactual Verification'}
            </button>
          </div>
        </div>

        {/* Experiment Results Overview */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                Verification Verdict: {activeExp?.pcap_name || 'No experiment run'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                {activeExp?.run_id} | Status: {activeExp?.status?.toUpperCase()}
              </div>
            </div>
            {activeExp && (
              <span
                className={`badge ${
                  activeExp.stability_verdict === 'STABLE'
                    ? 'badge-healthy'
                    : activeExp.stability_verdict === 'SENSITIVE'
                    ? 'badge-degraded'
                    : 'badge-unknown'
                }`}
                style={{ fontSize: '12px', padding: '4px 10px' }}
              >
                {activeExp.stability_verdict}
              </span>
            )}
          </div>

          {activeExp?.status === 'running' ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              <Clock size={28} className="animate-spin" style={{ margin: '0 auto 10px', color: 'var(--accent-amber)' }} />
              <div>Reprocessing capture under baseline and {(activeExp.drop_rate * 100).toFixed(0)}% loss scenario...</div>
            </div>
          ) : activeExp?.status === 'completed' ? (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '14px' }}>
                <div className="stat-box">
                  <div className="stat-label">Baseline Threat Windows</div>
                  <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {activeExp.comparison.baseline_suspicious_count}
                  </div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Perturbed Threat Windows</div>
                  <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {activeExp.comparison.perturbed_suspicious_count}
                  </div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Decision Shifts</div>
                  <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: activeExp.comparison.decision_shifts ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
                    {activeExp.comparison.decision_shifts} windows
                  </div>
                </div>
              </div>

              {/* Verdict Explanation */}
              <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '12px' }}>
                <CheckCircle2 size={16} />
                <div>
                  {activeExp.stability_verdict === 'STABLE' && (
                    <span>
                      <strong>STABLE:</strong> Suspicious classification remained resilient and unchanged under simulated {(activeExp.drop_rate * 100).toFixed(0)}% observation omission.
                    </span>
                  )}
                  {activeExp.stability_verdict === 'SENSITIVE' && (
                    <span>
                      <strong>SENSITIVE:</strong> Classification changed or weakened when {(activeExp.drop_rate * 100).toFixed(0)}% loss was injected. Additional corroborating network telemetry recommended before taking response actions.
                    </span>
                  )}
                  {activeExp.stability_verdict === 'INCONCLUSIVE' && (
                    <span>
                      <strong>INCONCLUSIVE:</strong> Input capture contained only benign baseline traffic; no threat findings were available to test for sensitivity.
                    </span>
                  )}
                </div>
              </div>

              {/* Non-Mutation Principle */}
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                <strong>Non-Mutation Guarantee:</strong> Counterfactual verification results are recorded alongside the original alert for analyst review; they never overwrite or suppress original detections.
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              Configure a scenario and click "Run Counterfactual Verification" to evaluate observation stability.
            </div>
          )}
        </div>
      </div>

      {/* Feature Shift Comparison Table */}
      {activeExp?.status === 'completed' && activeExp.comparison?.feature_shifts && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <TrendingDown size={16} style={{ color: 'var(--accent-amber)' }} />
              Feature Shifts: Baseline vs Perturbed Run
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Injected Omission: {(activeExp.drop_rate * 100).toFixed(0)}% ({activeExp.loss_mode})
            </div>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feature Metric</th>
                  <th>Baseline Value (0% Loss)</th>
                  <th>Perturbed Value ({(activeExp.drop_rate * 100).toFixed(0)}% Loss)</th>
                  <th>Absolute Shift</th>
                  <th>Relative Delta</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(activeExp.comparison.feature_shifts).map(([feat, shift]) => (
                  <tr key={feat}>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{feat}</td>
                    <td>{shift.baseline.toFixed(3)}</td>
                    <td>{shift.perturbed.toFixed(3)}</td>
                    <td style={{ color: shift.difference !== 0 ? 'var(--accent-amber)' : 'var(--text-muted)' }}>
                      {shift.difference > 0 ? `+${shift.difference.toFixed(3)}` : shift.difference.toFixed(3)}
                    </td>
                    <td>
                      {shift.percentage_change !== null ? (
                        <span>{shift.percentage_change > 0 ? `+${shift.percentage_change}%` : `${shift.percentage_change}%`}</span>
                      ) : (
                        '-'
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Past Experiments History */}
      {pastExperiments.length > 0 && (
        <div className="card" style={{ marginTop: '18px' }}>
          <div className="card-header">
            <div className="card-title">
              <History size={16} style={{ color: 'var(--accent-cyan)' }} />
              Replay Experiment History ({pastExperiments.length})
            </div>
          </div>
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>PCAP File</th>
                  <th>Loss Profile</th>
                  <th>Loss Rate</th>
                  <th>Seed</th>
                  <th>Stability Verdict</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {pastExperiments.map((exp) => (
                  <tr key={exp.run_id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{exp.run_id}</td>
                    <td>{exp.pcap_name}</td>
                    <td>{exp.loss_mode}</td>
                    <td>{(exp.drop_rate * 100).toFixed(0)}%</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{exp.seed}</td>
                    <td>
                      <span className={`badge ${
                        exp.stability_verdict === 'STABLE'
                          ? 'badge-healthy'
                          : exp.stability_verdict === 'SENSITIVE'
                          ? 'badge-degraded'
                          : 'badge-unknown'
                      }`}>
                        {exp.stability_verdict}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${exp.status === 'completed' ? 'badge-healthy' : 'badge-unknown'}`}>
                        {exp.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '3px 8px', fontSize: '11px' }}
                        onClick={() => setActiveExp(exp)}
                      >
                        Inspect Run
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
