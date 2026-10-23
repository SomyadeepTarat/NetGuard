import React, { useState } from 'react'
import { Activity, ShieldCheck, Cpu, HelpCircle, ArrowRight } from 'lucide-react'
import type { OverviewData, TimeseriesPoint } from '../types'

interface OverviewViewProps {
  overview: OverviewData | null
  timeseries: TimeseriesPoint[]
  onNavigateToAlerts: () => void
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  overview,
  timeseries,
  onNavigateToAlerts,
}) => {
  const [rateWindow, setRateWindow] = useState<'1s' | '5s' | '30s'>('5s')

  if (!overview) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
        <Activity size={32} className="animate-spin" style={{ margin: '0 auto 12px', color: 'var(--accent-cyan)' }} />
        <div style={{ color: 'var(--text-secondary)' }}>Connecting to NetGuard telemetry engine...</div>
      </div>
    )
  }

  // Calculate rate display based on window
  const activeRate = overview.rates?.[rateWindow]
  const currentPktsRate = activeRate ? activeRate.packets_per_sec : overview.packets_per_second
  const currentBytesRate = activeRate ? activeRate.bytes_per_sec : overview.bytes_per_second

  const quality = overview.capture_quality
  const isHealthy = quality.overall_status === 'HEALTHY'
  const isDegraded = quality.overall_status === 'DEGRADED'

  // Format bytes helper
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  // Build SVG path for timeseries sparkline
  const chartPoints = timeseries.slice(-60)
  const maxPkts = Math.max(...chartPoints.map((p) => p.packets_per_sec), 10)
  const svgWidth = 800
  const svgHeight = 120

  const polyPoints = chartPoints
    .map((pt, idx) => {
      const x = (idx / Math.max(chartPoints.length - 1, 1)) * svgWidth
      const y = svgHeight - (pt.packets_per_sec / maxPkts) * (svgHeight - 20) - 10
      return `${x},${y}`
    })
    .join(' ')

  return (
    <div>
      {/* Metric Stat Boxes */}
      <div className="stats-grid">
        <div className="stat-box">
          <div className="stat-label">
            <span>Engine Throughput</span>
            <div style={{ display: 'flex', gap: '4px' }}>
              {(['1s', '5s', '30s'] as const).map((w) => (
                <button
                  key={w}
                  style={{
                    background: rateWindow === w ? 'var(--accent-cyan-bg)' : 'transparent',
                    border: '1px solid',
                    borderColor: rateWindow === w ? 'var(--accent-cyan-border)' : 'transparent',
                    color: rateWindow === w ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    borderRadius: '4px',
                    fontSize: '10px',
                    padding: '1px 4px',
                    cursor: 'pointer',
                  }}
                  onClick={() => setRateWindow(w)}
                >
                  {w}
                </button>
              ))}
            </div>
          </div>
          <div className="stat-value">{currentPktsRate.toLocaleString()} <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>pkts/s</span></div>
          <div className="stat-sub">{formatBytes(currentBytesRate)}/s rolling average</div>
        </div>

        <div className="stat-box">
          <div className="stat-label">Active Connections</div>
          <div className="stat-value">{overview.active_flows}</div>
          <div className="stat-sub">Across {overview.active_hosts} observed hosts</div>
        </div>

        <div className="stat-box">
          <div className="stat-label">Cumulative Volume</div>
          <div className="stat-value">{overview.total_packets.toLocaleString()}</div>
          <div className="stat-sub">{formatBytes(overview.total_bytes)} metadata inspected</div>
        </div>

        <div className="stat-box">
          <div className="stat-label">Observation Fidelity</div>
          <div className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className={`badge ${
                isHealthy ? 'badge-healthy' : isDegraded ? 'badge-degraded' : 'badge-unknown'
              }`}
            >
              {quality.overall_status}
            </span>
          </div>
          <div className="stat-sub" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '6px' }}>
            <span>{overview.recent_alerts_count} recorded incidents</span>
            <button
              className="btn btn-secondary"
              style={{ padding: '2px 6px', fontSize: '10px' }}
              onClick={onNavigateToAlerts}
            >
              Inspect <ArrowRight size={10} />
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Throughput Area Chart */}
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">
              <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
              Live Ingestion Throughput (Last 60 Seconds)
            </div>
            <div className="card-desc">
              Packets per second delivered to the bounded analysis worker.
            </div>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
            Peak: {maxPkts.toFixed(0)} pkts/s
          </div>
        </div>

        <div className="chart-container">
          {chartPoints.length > 1 ? (
            <svg
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              preserveAspectRatio="none"
              style={{ width: '100%', height: '100%', overflow: 'visible' }}
            >
              <defs>
                <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              {/* Filled area */}
              <polygon
                points={`0,${svgHeight} ${polyPoints} ${svgWidth},${svgHeight}`}
                fill="url(#cyanGrad)"
              />
              {/* Stroke line */}
              <polyline
                points={polyPoints}
                fill="none"
                stroke="#06b6d4"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          ) : (
            <div style={{ textAlign: 'center', paddingTop: '40px', color: 'var(--text-muted)', fontSize: '12px' }}>
              Buffering timeseries points...
            </div>
          )}
        </div>
      </div>

      {/* Protocol Breakdown & Capture Quality Split */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '18px' }}>
        {/* Protocol Breakdown */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <Cpu size={16} style={{ color: 'var(--accent-cyan)' }} />
              Protocol Distribution
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {Object.entries(overview.protocols).map(([proto, count]) => {
              const pct = overview.total_packets > 0 ? (count / overview.total_packets) * 100 : 0
              return (
                <div key={proto}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                    <span>{proto}</span>
                    <span>{count.toLocaleString()} ({pct.toFixed(1)}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'var(--bg-surface-elevated)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: proto === 'TCP' ? '#06b6d4' : proto === 'UDP' ? '#0ea5e9' : proto === 'ICMP' ? '#f59e0b' : '#64748b' }} />
                  </div>
                </div>
              )
            })}
          </div>

          {/* Extended Protocols */}
          <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            <span className="badge badge-unavailable">IPv6: {overview.extended_protocols.IPv6 || 0}</span>
            <span className="badge badge-unavailable">ICMPv6: {overview.extended_protocols.ICMPv6 || 0}</span>
            <span className="badge badge-unavailable">ARP: {overview.extended_protocols.ARP || 0}</span>
            <span className="badge badge-unavailable">DNS Observed: {overview.extended_protocols.DNS || 0}</span>
          </div>
        </div>

        {/* Capture Quality Telemetry Subsystem (Core Differentiator) */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <ShieldCheck size={16} style={{ color: isHealthy ? 'var(--accent-emerald)' : 'var(--accent-amber)' }} />
                Capture Quality & Telemetry Observability
              </div>
              <div className="card-desc">
                Source attribution and health of observation channels.
              </div>
            </div>
          </div>

          <div className="callout callout-info" style={{ marginTop: '0', marginBottom: '14px' }}>
            <HelpCircle size={15} style={{ flexShrink: 0 }} />
            <div>
              <strong>Separation Principle:</strong> Capture fidelity represents observation completeness, not threat severity. Missing telemetry is reported as <code>UNAVAILABLE</code>, never assumed to be 0% loss.
            </div>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Observation Metric</th>
                  <th>Value</th>
                  <th>Status</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {quality.indicators.map((ind, i) => (
                  <tr key={i} title={ind.limitations}>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{ind.name}</td>
                    <td>{ind.value !== null ? ind.value : <span style={{ color: 'var(--text-muted)' }}>Unavailable</span>}</td>
                    <td>
                      <span className={`badge badge-${ind.status.toLowerCase()}`}>
                        {ind.status}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{ind.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
