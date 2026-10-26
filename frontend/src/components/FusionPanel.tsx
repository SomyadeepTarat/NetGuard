import type { FusionResult, OverviewData } from '../types'

export function FusionEvidence({ result }: { result: FusionResult }) {
  if (result.status !== 'READY') return <p>Reference warming up: {result.reference_windows ?? 0} / {result.reference_target ?? '—'} windows. {result.reference_scope}</p>
  return <div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
      <div>Joint empirical p<br /><strong>{result.p_value?.toFixed(4)}</strong></div>
      <div>Feature / peer p<br /><strong>{result.feature_p_value?.toFixed(4)} / {result.graph_p_value?.toFixed(4)}</strong></div>
      <div>Temporal evidence<br /><strong>{result.temporal_evidence?.toFixed(2)} / {result.temporal_threshold}</strong></div>
      <div>Visibility test<br /><strong>{result.visibility?.status?.replaceAll('_', ' ') ?? 'Unavailable'}</strong></div>
    </div>
    <p style={{ marginTop: 12, color: 'var(--color-text-secondary)' }}>
      {result.is_anomalous ? 'Persistent anomaly detected.' : result.instant_candidate ? 'Unusual window; awaiting temporal corroboration.' : 'Window within the frozen reference envelope.'}
      {' '}Empirical ranks describe departure from the reference; they are not attack probabilities.
    </p>
    {result.top_deviations?.map(item => <span className="badge badge-unknown" style={{ margin: '4px 8px 0 0' }} key={item.feature}>{item.feature}: {item.robust_deviation.toFixed(1)}</span>)}
  </div>
}

export function FusionPanel({ overview }: { overview: OverviewData | null }) {
  const status = overview?.research_fusion
  return <section className="card" style={{ padding: 20, marginBottom: 20 }}>
    <div className="card-header">
      <h2 className="card-title">Observation-aware evidence fusion</h2>
      <span className={`badge ${status?.ready ? 'badge-healthy' : 'badge-unknown'}`}>{status?.ready ? 'REFERENCE READY' : 'REFERENCE WARM-UP'}</span>
    </div>
    <p style={{ color: 'var(--color-text-secondary)', marginBottom: 12 }}>{overview?.source_selection?.automatic ? 'Automatic source · ' : ''}{overview?.source_selection?.reason ?? 'Waiting for ingestion status.'}</p>
    {overview?.error && <p role="alert" style={{ color: 'var(--color-warning)' }}>{overview.error}</p>}
    <p style={{ marginBottom: 14 }}>Robust covariance + peer/service novelty + empirical calibration + temporal accumulation + visibility sensitivity.</p>
    {status?.last_result ? <FusionEvidence result={status.last_result} /> : <p>No detection windows yet.</p>}
    <p style={{ color: 'var(--color-text-muted)', fontSize: 12, marginTop: 12 }}>Experimental method · {status?.reference_windows ?? 0} reference windows · {status?.reference_scope ?? 'No reference'} · {status?.evaluated_windows ?? 0} scored windows</p>
  </section>
}
