import { useEffect, useState } from 'react'
import { api } from '../api'

export function FusionEvaluation() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.getFusionEvaluation>> | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { api.getFusionEvaluation().then(setData).catch(e => setError(String(e))) }, [])
  const totals = new Map<string, { tp: number; fp: number; fn: number; tn: number; abstentions: number }>()
  for (const run of data?.report?.runs ?? []) for (const row of run.results) {
    const sum = totals.get(row.method) ?? { tp: 0, fp: 0, fn: 0, tn: 0, abstentions: 0 }
    for (const key of ['tp', 'fp', 'fn', 'tn', 'abstentions'] as const) sum[key] += row[key]
    totals.set(row.method, sum)
  }
  return <section className="card" style={{ padding: 20, marginBottom: 20 }}>
    <h2 className="card-title">Fusion experiment and component ablations</h2>
    <p style={{ margin: '12px 0', color: 'var(--color-text-secondary)' }}>Scope: {data?.report?.scope ?? 'Not evaluated'}. Synthetic feature fixtures check mechanisms; public dataset validation is still required. Fusion rows evaluate the new branch independently of the retained rule and SVM branches.</p>
    {error && <p role="alert">{error}</p>}
    {totals.size ? <div style={{ overflowX: 'auto' }}><table className="data-table"><thead><tr><th>Method</th><th>Precision</th><th>Recall</th><th>Binary F1</th><th>False positive windows</th><th>Abstentions</th></tr></thead><tbody>
      {[...totals].map(([method, s]) => <tr key={method}><td>{method.replaceAll('_', ' ')}</td><td>{(s.tp / Math.max(s.tp + s.fp, 1)).toFixed(3)}</td><td>{(s.tp / Math.max(s.tp + s.fn, 1)).toFixed(3)}</td><td>{(2 * s.tp / Math.max(2 * s.tp + s.fp + s.fn, 1)).toFixed(3)}</td><td>{s.fp} / {s.fp + s.tn}</td><td>{s.abstentions}</td></tr>)}
    </tbody></table></div> : <p>Generate a report with <code>python -m backend.ml.evaluate_fusion</code>.</p>}
  </section>
}
