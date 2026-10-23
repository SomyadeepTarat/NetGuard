import React, { useEffect, useState } from 'react'
import { Award, BookOpen, Layers, HelpCircle } from 'lucide-react'
import type { EvaluationData } from '../types'
import { api } from '../api'

export const EvaluationView: React.FC = () => {
  const [data, setData] = useState<EvaluationData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedLoss, setSelectedLoss] = useState<string>('0')

  useEffect(() => {
    const fetchEval = async () => {
      try {
        const res = await api.getEvaluation()
        setData(res)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    fetchEval()
  }, [])

  if (loading) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
        <Award size={32} className="animate-spin" style={{ margin: '0 auto 12px', color: 'var(--accent-cyan)' }} />
        <div style={{ color: 'var(--text-secondary)' }}>Loading evaluation report...</div>
      </div>
    )
  }

  if (!data || data.status === 'NOT_EVALUATED') {
    return (
      <div className="card" style={{ padding: '30px', textAlign: 'center' }}>
        <HelpCircle size={36} style={{ color: 'var(--accent-amber)', margin: '0 auto 14px' }} />
        <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px' }}>
          Research Model: Not Yet Evaluated
        </h3>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto 16px', fontSize: '13px' }}>
          NetGuard follows strict academic honesty: evaluation metrics are never manufactured or hard-coded. To generate verified metrics on locally generated demo sessions, run:
        </p>
        <code style={{ background: 'var(--bg-surface-elevated)', padding: '6px 12px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-cyan)' }}>
          python -m backend.ml train --manifest artifacts/demo/manifest.json
        </code>
      </div>
    )
  }

  const testReport = data.tests?.[selectedLoss]
  const mlReport = testReport?.ml
  const classification = mlReport?.classification || {}
  const confusion = mlReport?.confusion_matrix || []
  const confusionLabels = mlReport?.confusion_labels || []

  return (
    <div>
      {/* Methodology & Provenance Banner */}
      <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '16px' }}>
        <BookOpen size={18} style={{ flexShrink: 0 }} />
        <div>
          <strong>Provenance Scope: {data.scope}</strong> | Scikit-learn Version: {data.sklearn_version} | Threshold: {data.threshold}
          <div style={{ fontSize: '11px', marginTop: '2px', color: 'var(--text-muted)' }}>
            {data.disclaimer}
          </div>
        </div>
      </div>

      {/* Perturbation Level Selector */}
      <div className="card" style={{ padding: '12px 18px', marginBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Evaluation Injected Loss Level:
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {['0', '0.1', '0.3'].map((loss) => (
              <button
                key={loss}
                className="btn btn-secondary"
                style={{
                  background: selectedLoss === loss ? 'var(--accent-cyan-bg)' : undefined,
                  borderColor: selectedLoss === loss ? 'var(--accent-cyan-border)' : undefined,
                  color: selectedLoss === loss ? 'var(--accent-cyan)' : undefined,
                }}
                onClick={() => setSelectedLoss(loss)}
              >
                {loss === '0' ? 'Baseline (0% Loss)' : `${parseFloat(loss) * 100}% Injected Loss`}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Macro Scores */}
      {mlReport && (
        <div className="stats-grid">
          <div className="stat-box">
            <div className="stat-label">Macro Average F1-Score</div>
            <div className="stat-value" style={{ color: 'var(--accent-emerald)' }}>
              {classification['macro avg']?.['f1-score']?.toFixed(3) || 'N/A'}
            </div>
            <div className="stat-sub">Across all four target classes</div>
          </div>

          <div className="stat-box">
            <div className="stat-label">False Alerts / Benign Hour</div>
            <div className="stat-value">
              {mlReport.false_alerts_per_hour !== null ? mlReport.false_alerts_per_hour.toFixed(2) : '0.00'}
            </div>
            <div className="stat-sub">Over {mlReport.benign_observation_seconds.toFixed(0)}s benign exposure</div>
          </div>

          <div className="stat-box">
            <div className="stat-label">Evaluation Windows</div>
            <div className="stat-value">{testReport?.windows || 0}</div>
            <div className="stat-sub">{testReport?.batch_inference_windows_per_second?.toFixed(0)} windows/sec throughput</div>
          </div>
        </div>
      )}

      {/* Classification Report Table & Confusion Matrix Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '18px', marginBottom: '18px' }}>
        {/* Classification Metrics Table */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Award size={16} style={{ color: 'var(--accent-cyan)' }} />
              Per-Class Classification Metrics
            </div>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Class</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1-Score</th>
                  <th>Support</th>
                </tr>
              </thead>
              <tbody>
                {['BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'].map((cls) => {
                  const m = classification[cls]
                  if (!m) return null
                  return (
                    <tr key={cls}>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{cls}</td>
                      <td>{m.precision.toFixed(3)}</td>
                      <td>{m.recall.toFixed(3)}</td>
                      <td style={{ color: 'var(--accent-cyan)' }}>{m['f1-score'].toFixed(3)}</td>
                      <td>{m.support}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Confusion Matrix */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Layers size={16} style={{ color: 'var(--accent-cyan)' }} />
              Confusion Matrix (True vs Predicted)
            </div>
          </div>

          {confusion.length > 0 ? (
            <div className="table-responsive">
              <table className="data-table" style={{ textAlign: 'center' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left' }}>True \ Pred</th>
                    {confusionLabels.map((lbl) => (
                      <th key={lbl}>{lbl}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {confusion.map((row, rIdx) => (
                    <tr key={rIdx}>
                      <td style={{ textAlign: 'left', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {confusionLabels[rIdx]}
                      </td>
                      {row.map((cell, cIdx) => {
                        const isDiagonal = rIdx === cIdx
                        return (
                          <td
                            key={cIdx}
                            style={{
                              background: isDiagonal ? 'rgba(16, 185, 129, 0.15)' : cell > 0 ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
                              color: isDiagonal ? '#34d399' : cell > 0 ? '#fb7185' : 'var(--text-muted)',
                              fontWeight: isDiagonal || cell > 0 ? 600 : 400,
                            }}
                          >
                            {cell}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '20px', textAlign: 'center' }}>
              No confusion matrix available for this evaluation run.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
