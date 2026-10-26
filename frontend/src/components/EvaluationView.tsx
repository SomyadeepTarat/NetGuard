import React, { useEffect, useState } from 'react'
import {
  Award,
  BookOpen,
  Copy,
  Check,
  RefreshCw,
  Sliders,
  Activity
} from 'lucide-react'
import type { EvaluationData } from '../types'
import { api } from '../api'
import { FusionEvaluation } from './FusionEvaluation'
import { PageHeader } from './PageHeader'

export const EvaluationView: React.FC = () => {
  const [data, setData] = useState<EvaluationData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedLoss, setSelectedLoss] = useState<string>('0')
  const [copied, setCopied] = useState(false)

  const fetchEval = async () => {
    setLoading(true)
    try {
      const res = await api.getEvaluation()
      setData(res)
    } catch (e) {
      console.error('Failed to load evaluation metrics:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEval()
  }, [])

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <FusionEvaluation />
      {/* Page Header */}
      <PageHeader
        title="Model Evaluation & Empirical Benchmark"
        description="Supervised classification metrics, class-wise F1, confusion matrices, and throughput under baseline and perturbed observations."
        icon={<Award size={20} />}
        badge={
          data?.status === 'EVALUATED' ? (
            <span className="badge badge-healthy">BENCHMARKED ARTIFACT</span>
          ) : (
            <span className="badge badge-unknown">EVALUATION PENDING</span>
          )
        }
        actions={
          <button
            className="btn btn-secondary"
            onClick={fetchEval}
            disabled={loading}
            title="Reload evaluation report"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Reload</span>
          </button>
        }
      />

      {loading ? (
        <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <RefreshCw size={28} className="animate-spin" style={{ margin: '0 auto 14px', color: 'var(--color-accent)' }} />
          <div style={{ color: 'var(--color-text-secondary)', fontSize: '13px' }}>
            Reading verified model evaluation artifacts...
          </div>
        </div>
      ) : !data || data.status === 'NOT_EVALUATED' ? (
        /* Academic Honesty / Not Yet Evaluated State */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="card" style={{ padding: '36px 28px', textAlign: 'center' }}>
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                background: 'var(--color-surface-muted)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
                color: 'var(--color-warning)',
              }}
            >
              <BookOpen size={24} />
            </div>
            <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '8px' }}>
              Academic Integrity: Evaluation Artifact Pending
            </h3>
            <p
              style={{
                color: 'var(--color-text-secondary)',
                maxWidth: '580px',
                margin: '0 auto 20px',
                fontSize: '13px',
                lineHeight: 1.55,
              }}
            >
              NetGuard enforces strict academic honesty: model evaluation metrics are never synthesized, hard-coded, or inferred. Verified benchmark scores require executing the reproducible training and test protocol against authorized PCAP manifests.
            </p>

            {/* Copyable CLI Command Box */}
            <div
              style={{
                maxWidth: '620px',
                margin: '0 auto 24px',
                background: 'var(--color-shell)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
                boxShadow: 'var(--shadow-sm)',
              }}
            >
              <code
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12.5px',
                  color: '#93c5fd',
                  textAlign: 'left',
                  overflowX: 'auto',
                }}
              >
                python -m backend.ml train --manifest artifacts/demo/manifest.json
              </code>
              <button
                className="btn btn-secondary"
                style={{
                  padding: '4px 10px',
                  fontSize: '11px',
                  background: 'rgba(255, 255, 255, 0.1)',
                  borderColor: 'rgba(255, 255, 255, 0.2)',
                  color: '#ffffff',
                }}
                onClick={() =>
                  copyCommand('python -m backend.ml train --manifest artifacts/demo/manifest.json')
                }
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy Command'}</span>
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', maxWidth: '720px', margin: '0 auto', textAlign: 'left' }}>
              <div style={{ padding: '12px', background: 'var(--color-surface-hover)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-subtle)' }}>
                <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                  1. Multi-Class Ground Truth
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--color-text-secondary)' }}>
                  Evaluates against Port Scan, SYN Flood, Traffic Flood, and Benign PCAP traces.
                </div>
              </div>

              <div style={{ padding: '12px', background: 'var(--color-surface-hover)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-subtle)' }}>
                <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                  2. Perturbation Resiliency
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--color-text-secondary)' }}>
                  Tests classification stability across 0%, 10%, and 30% injected packet omission.
                </div>
              </div>

              <div style={{ padding: '12px', background: 'var(--color-surface-hover)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-subtle)' }}>
                <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--color-text-primary)', marginBottom: '4px' }}>
                  3. False Alarm Calibration
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--color-text-secondary)' }}>
                  Measures false alerts per hour over continuous benign network traffic exposure.
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Verified Evaluation Report View */
        (() => {
          const testReport = data.tests?.[selectedLoss]
          const mlReport = testReport?.ml
          const classification = mlReport?.classification || {}
          const confusion = mlReport?.confusion_matrix || []
          const confusionLabels = mlReport?.confusion_labels || []

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Provenance & Methodology Banner */}
              <div className="callout callout-info" style={{ marginTop: 0, marginBottom: 0 }}>
                <BookOpen size={18} style={{ flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600 }}>
                    Provenance Scope: {data.scope || 'Trained on reproducible demo PCAP manifest'}
                  </div>
                  <div style={{ fontSize: '12px', marginTop: '2px', color: 'var(--color-text-secondary)' }}>
                    Scikit-learn Engine: {data.sklearn_version || '1.x'} | Decision Threshold: {data.threshold ?? 0.5} | {data.disclaimer || 'Empirical benchmark results.'}
                  </div>
                </div>
              </div>

              {/* Perturbation Level Selector */}
              <div className="card" style={{ padding: '12px 18px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Evaluation Injected Loss Level:
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {Object.keys(data.tests || { '0': {} }).map((loss) => (
                      <button
                        key={loss}
                        type="button"
                        className="btn btn-secondary"
                        style={{
                          fontSize: '11.5px',
                          fontWeight: 600,
                          background: selectedLoss === loss ? 'var(--color-accent)' : undefined,
                          borderColor: selectedLoss === loss ? 'var(--color-accent)' : undefined,
                          color: selectedLoss === loss ? '#ffffff' : undefined,
                        }}
                        onClick={() => setSelectedLoss(loss)}
                      >
                        {loss === '0'
                          ? 'Baseline (0% Loss)'
                          : `${(parseFloat(loss) * 100).toFixed(0)}% Injected Loss`}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Macro Benchmark Scores */}
              {mlReport && (
                <div className="stats-grid">
                  <div className="stat-box">
                    <div className="stat-label">Macro Average F1-Score</div>
                    <div className="stat-value" style={{ color: 'var(--color-healthy)' }}>
                      {classification['macro avg']?.['f1-score']?.toFixed(3) || 'N/A'}
                    </div>
                    <div className="stat-sub">Harmonic mean across all target classes</div>
                  </div>

                  <div className="stat-box">
                    <div className="stat-label">False Alerts / Benign Hour</div>
                    <div className="stat-value">
                      {mlReport.false_alerts_per_hour !== null
                        ? mlReport.false_alerts_per_hour.toFixed(2)
                        : '0.00'}
                    </div>
                    <div className="stat-sub">
                      Over {mlReport.benign_observation_seconds?.toFixed(0) || 0}s benign exposure
                    </div>
                  </div>

                  <div className="stat-box">
                    <div className="stat-label">Inference Windows Tested</div>
                    <div className="stat-value">{testReport?.windows || 0}</div>
                    <div className="stat-sub">
                      {testReport?.batch_inference_windows_per_second?.toFixed(0) || 0} windows/sec throughput
                    </div>
                  </div>
                </div>
              )}

              {/* Class-wise Metrics Table */}
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <div
                  style={{
                    padding: '14px 18px',
                    borderBottom: '1px solid var(--color-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div className="card-title" style={{ fontSize: '13px' }}>
                    <Sliders size={15} style={{ color: 'var(--color-accent)' }} />
                    Class-wise Precision, Recall, and F1 Metrics
                  </div>
                </div>

                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Detector Class</th>
                        <th style={{ textAlign: 'right' }}>Precision</th>
                        <th style={{ textAlign: 'right' }}>Recall</th>
                        <th style={{ textAlign: 'right' }}>F1-Score</th>
                        <th style={{ textAlign: 'right' }}>Support (Windows)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(classification)
                        .filter(([k]) => typeof classification[k] === 'object' && 'f1-score' in classification[k])
                        .map(([className, metrics]: [string, any]) => {
                          const isAvg = className.includes('avg')
                          return (
                            <tr
                              key={className}
                              style={{
                                fontWeight: isAvg ? 600 : 400,
                                background: isAvg ? 'var(--color-surface-hover)' : undefined,
                              }}
                            >
                              <td style={{ fontFamily: 'var(--font-mono)' }}>{className}</td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {metrics.precision?.toFixed(3)}
                              </td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {metrics.recall?.toFixed(3)}
                              </td>
                              <td
                                style={{
                                  textAlign: 'right',
                                  fontFamily: 'var(--font-mono)',
                                  fontWeight: 600,
                                  color: metrics['f1-score'] > 0.8 ? 'var(--color-healthy)' : undefined,
                                }}
                              >
                                {metrics['f1-score']?.toFixed(3)}
                              </td>
                              <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                                {metrics.support}
                              </td>
                            </tr>
                          )
                        })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Confusion Matrix Visualization */}
              {confusion.length > 0 && (
                <div className="card" style={{ padding: '20px' }}>
                  <div className="card-header" style={{ marginBottom: '14px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Activity size={15} style={{ color: 'var(--color-accent)' }} />
                      Empirical Confusion Matrix
                    </div>
                    <div className="card-desc">
                      Rows: Ground Truth Class | Columns: Predicted Classification
                    </div>
                  </div>

                  <div className="table-responsive">
                    <table className="data-table" style={{ textAlign: 'center' }}>
                      <thead>
                        <tr>
                          <th style={{ textAlign: 'left' }}>True \ Pred</th>
                          {confusionLabels.map((lbl) => (
                            <th key={lbl} style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '10.5px' }}>
                              {lbl}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {confusion.map((row, rIdx) => {
                          const rowSum = row.reduce((a, b) => a + b, 0)
                          return (
                            <tr key={rIdx}>
                              <td style={{ textAlign: 'left', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                                {confusionLabels[rIdx] || `Class ${rIdx}`}
                              </td>
                              {row.map((val, cIdx) => {
                                const isDiagonal = rIdx === cIdx
                                const fraction = rowSum > 0 ? val / rowSum : 0
                                return (
                                  <td
                                    key={cIdx}
                                    style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontWeight: isDiagonal ? 700 : 400,
                                      background:
                                        isDiagonal && val > 0
                                          ? `rgba(15, 118, 110, ${Math.max(0.08, fraction * 0.4)})`
                                          : !isDiagonal && val > 0
                                          ? `rgba(190, 18, 60, ${Math.max(0.08, fraction * 0.4)})`
                                          : undefined,
                                    }}
                                  >
                                    {val}
                                  </td>
                                )
                              })}
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )
        })()
      )}
    </div>
  )
}

export default EvaluationView
