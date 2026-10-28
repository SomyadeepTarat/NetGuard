import React, { useState } from 'react'
import {
  Activity,
  ShieldCheck,
  Cpu,
  HelpCircle,
  ArrowRight,
  TrendingUp,
  Zap,
  Layers
} from 'lucide-react'
import type { OverviewData, TimeseriesPoint } from '../types'
import { PageHeader } from './PageHeader'

interface OverviewViewProps {
  overview: OverviewData | null
  timeseries: TimeseriesPoint[]
  onNavigateToAlerts: () => void
  onNavigateToFlows: () => void
  onNavigateToHosts: () => void
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  overview,
  timeseries,
  onNavigateToAlerts,
  onNavigateToFlows,
  onNavigateToHosts,
}) => {
  const [rateWindow, setRateWindow] = useState<'1s' | '5s' | '30s'>('5s')
  const [hoveredPoint, setHoveredPoint] = useState<TimeseriesPoint | null>(null)

  if (!overview) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '60px 20px' }}>
        <Activity size={32} className="animate-spin" style={{ margin: '0 auto 14px', color: 'var(--color-accent)' }} />
        <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '4px' }}>
          Connecting to NetGuard Telemetry Engine...
        </h3>
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '12.5px' }}>
          Initializing sliding-window telemetry buffers and capture handle.
        </p>
      </div>
    )
  }

  // Calculate rate display based on active window
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
  const svgWidth = 840
  const svgHeight = 150

  const polyPoints = chartPoints
    .map((pt, idx) => {
      const x = (idx / Math.max(chartPoints.length - 1, 1)) * svgWidth
      const y = svgHeight - (pt.packets_per_sec / maxPkts) * (svgHeight - 24) - 12
      return `${x},${y}`
    })
    .join(' ')

  return (
    <div>
      {/* Page Title & Context Header */}
      <PageHeader
        title="Network Telemetry & Health Overview"
        description="Real-time multi-protocol packet ingestion, sliding throughput telemetry, flow aggregation, and observation fidelity."
        icon={<Activity size={20} />}
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className={`badge ${
                overview.status === 'CAPTURING' ? 'badge-healthy' : 'badge-unavailable'
              }`}
            >
              {overview.status}
            </span>
          </div>
        }
      />

      {/* Mode & Environment Notice Banner */}
      {overview.mode === 'DEMO' && (
        <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '20px' }}>
          <Zap size={16} style={{ flexShrink: 0 }} />
          <div>
            <strong>Synthetic Demonstration Environment:</strong> Ingesting bounded multi-protocol traffic fixtures to evaluate flow aggregation and classifier behavior. Packet timestamps and sliding-window rates are synchronized in real time.
          </div>
        </div>
      )}

      {/* Key Metric Stat Boxes */}
      <div className="stats-grid">
        {/* Metric 1: Throughput */}
        <div className="stat-box">
          <div className="stat-label">
            <span>Engine Throughput</span>
            <div style={{ display: 'flex', gap: '4px' }}>
              {(['1s', '5s', '30s'] as const).map((w) => (
                <button
                  key={w}
                  style={{
                    background: rateWindow === w ? 'var(--color-accent)' : 'transparent',
                    border: '1px solid',
                    borderColor: rateWindow === w ? 'var(--color-accent)' : 'var(--color-border)',
                    color: rateWindow === w ? '#ffffff' : 'var(--color-text-secondary)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '10px',
                    fontWeight: 600,
                    padding: '1px 6px',
                    cursor: 'pointer',
                    transition: 'all 0.1s ease',
                  }}
                  onClick={() => setRateWindow(w)}
                >
                  {w}
                </button>
              ))}
            </div>
          </div>
          <div className="stat-value">
            {currentPktsRate.toLocaleString()}
            <span className="stat-unit">pkts/s</span>
          </div>
          <div className="stat-sub">
            {formatBytes(currentBytesRate)}/s ({rateWindow} rolling rate)
          </div>
        </div>

        {/* Metric 2: Active Connections */}
        <div
          className="stat-box"
          style={{ cursor: 'pointer' }}
          onClick={onNavigateToFlows}
          title="Click to open Live Traffic & Flows workspace"
        >
          <div className="stat-label">
            <span>Active Connections</span>
            <ArrowRight size={12} style={{ color: 'var(--color-text-muted)' }} />
          </div>
          <div className="stat-value">
            {overview.active_flows}
            <span className="stat-unit">flows</span>
          </div>
          <div className="stat-sub">
            Across{' '}
            <span
              style={{ textDecoration: 'underline', cursor: 'pointer' }}
              onClick={(e) => {
                e.stopPropagation()
                onNavigateToHosts()
              }}
              title="Click to explore observed endpoints in Host Explorer"
            >
              {overview.active_hosts} observed endpoints
            </span>
            {overview.total_flows !== undefined && overview.total_flows > overview.active_flows && (
              <span> ({overview.total_flows} retained)</span>
            )}
          </div>
        </div>

        {/* Metric 3: Cumulative Volume */}
        <div className="stat-box">
          <div className="stat-label">
            <span>Cumulative Volume</span>
            <Layers size={13} style={{ color: 'var(--color-text-muted)' }} />
          </div>
          <div className="stat-value">
            {overview.total_packets.toLocaleString()}
            <span className="stat-unit">pkts</span>
          </div>
          <div className="stat-sub">
            {formatBytes(overview.total_bytes)} wire metadata inspected
          </div>
        </div>

        {/* Metric 4: Observation Fidelity */}
        <div className="stat-box">
          <div className="stat-label">
            <span>Observation Fidelity</span>
            <ShieldCheck size={13} style={{ color: 'var(--color-text-muted)' }} />
          </div>
          <div className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className={`badge ${
                isHealthy
                  ? 'badge-healthy'
                  : isDegraded
                  ? 'badge-degraded'
                  : 'badge-unknown'
              }`}
              style={{ fontSize: '13px', padding: '3px 9px' }}
            >
              {quality.overall_status}
            </span>
          </div>
          <div className="stat-sub" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
            <span>{overview.recent_alerts_count} recorded incident{overview.recent_alerts_count === 1 ? '' : 's'}</span>
            <button
              className="btn btn-secondary"
              style={{ padding: '2px 7px', fontSize: '11px', height: '22px' }}
              onClick={onNavigateToAlerts}
            >
              Inspect <ArrowRight size={10} />
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Ingestion Throughput Timeline */}
      <div className="card" style={{ marginBottom: '22px' }}>
        <div className="card-header">
          <div>
            <div className="card-title">
              <TrendingUp size={16} style={{ color: 'var(--color-accent)' }} />
              Live Ingestion Throughput Timeline
            </div>
            <div className="card-desc">
              1-second sliding ingress rate delivered to bounded analysis worker (Last 60 seconds).
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {hoveredPoint && (
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  background: 'var(--color-surface-muted)',
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {hoveredPoint.iso_time}: <strong>{hoveredPoint.packets_per_sec.toFixed(0)} pkts/s</strong> ({formatBytes(hoveredPoint.bytes_per_sec)}/s)
              </div>
            )}
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--color-text-secondary)' }}>
              Peak: <strong style={{ color: 'var(--color-text-primary)' }}>{maxPkts.toFixed(0)} pkts/s</strong>
            </div>
          </div>
        </div>

        <div style={{ width: '100%', height: `${svgHeight}px`, position: 'relative' }}>
          {chartPoints.length > 1 ? (
            <svg
              viewBox={`0 0 ${svgWidth} ${svgHeight}`}
              preserveAspectRatio="none"
              style={{ width: '100%', height: '100%', overflow: 'visible' }}
            >
              <defs>
                <linearGradient id="cobaltGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#365cf5" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#365cf5" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1={svgHeight - 12} x2={svgWidth} y2={svgHeight - 12} stroke="var(--color-border)" strokeWidth="1" />
              <line x1="0" y1={svgHeight / 2} x2={svgWidth} y2={svgHeight / 2} stroke="var(--color-border-subtle)" strokeDasharray="3 3" />
              <line x1="0" y1="12" x2={svgWidth} y2="12" stroke="var(--color-border-subtle)" strokeDasharray="3 3" />

              {/* Filled Area */}
              <polygon
                points={`0,${svgHeight - 12} ${polyPoints} ${svgWidth},${svgHeight - 12}`}
                fill="url(#cobaltGradient)"
              />

              {/* Primary Stroke Line */}
              <polyline
                points={polyPoints}
                fill="none"
                stroke="var(--color-accent)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />

              {/* Data Point Circles on Hover/Latest */}
              {chartPoints.map((pt, idx) => {
                const x = (idx / Math.max(chartPoints.length - 1, 1)) * svgWidth
                const y = svgHeight - (pt.packets_per_sec / maxPkts) * (svgHeight - 24) - 12
                return (
                  <circle
                    key={idx}
                    cx={x}
                    cy={y}
                    r={hoveredPoint === pt ? 5 : 2}
                    fill={hoveredPoint === pt ? 'var(--color-accent)' : '#ffffff'}
                    stroke="var(--color-accent)"
                    strokeWidth={hoveredPoint === pt ? 2 : 1}
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setHoveredPoint(pt)}
                    onMouseLeave={() => setHoveredPoint(null)}
                  />
                )
              })}
            </svg>
          ) : (
            <div style={{ textAlign: 'center', paddingTop: '50px', color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
              Buffering sliding-window timeseries telemetry points...
            </div>
          )}
        </div>
      </div>

      {/* Two-Column Grid: Protocol Breakdown & Capture Quality Telemetry */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        {/* Column 1: Protocol Distribution */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <Cpu size={16} style={{ color: 'var(--color-accent)' }} />
                Protocol Distribution
              </div>
              <div className="card-desc">Observed L3/L4 transport frame breakdown.</div>
            </div>
            <span className="badge badge-unavailable">{overview.total_packets.toLocaleString()} Total</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {Object.entries(overview.protocols).map(([proto, count]) => {
              const pct = overview.total_packets > 0 ? (count / overview.total_packets) * 100 : 0
              const color =
                proto === 'TCP'
                  ? 'var(--proto-tcp)'
                  : proto === 'UDP'
                  ? 'var(--proto-udp)'
                  : proto === 'ICMP'
                  ? 'var(--proto-icmp)'
                  : 'var(--proto-other)'

              return (
                <div key={proto}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '5px' }}>
                    <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{proto}</span>
                    <span className="font-mono text-secondary">
                      {count.toLocaleString()} <span style={{ color: 'var(--color-text-muted)' }}>({pct.toFixed(1)}%)</span>
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '7px', background: 'var(--color-surface-sunken)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: color,
                        borderRadius: 'var(--radius-full)',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>

          {/* Extended Protocol Telemetry */}
          <div
            style={{
              marginTop: '18px',
              paddingTop: '14px',
              borderTop: '1px solid var(--color-border-subtle)',
              display: 'flex',
              flexWrap: 'wrap',
              gap: '8px',
            }}
          >
            <span className="badge badge-unavailable">
              IPv6: {overview.extended_protocols.IPv6 || 0}
            </span>
            <span className="badge badge-unavailable">
              ICMPv6: {overview.extended_protocols.ICMPv6 || 0}
            </span>
            <span className="badge badge-unavailable">
              ARP: {overview.extended_protocols.ARP || 0}
            </span>
            <span className="badge badge-unavailable">
              DNS Frames: {overview.extended_protocols.DNS || 0}
            </span>
            {overview.extended_protocols.PARSER_ERRORS > 0 && (
              <span className="badge badge-critical">
                Parser Errors: {overview.extended_protocols.PARSER_ERRORS}
              </span>
            )}
          </div>
        </div>

        {/* Column 2: Capture Quality Subsystem (Core Differentiator) */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">
                <ShieldCheck
                  size={16}
                  style={{ color: isHealthy ? 'var(--color-healthy)' : 'var(--color-warning)' }}
                />
                Capture Fidelity & Telemetry Integrity
              </div>
              <div className="card-desc">Source attribution and sensor health across capture layers.</div>
            </div>
            <span
              className={`badge ${
                isHealthy ? 'badge-healthy' : isDegraded ? 'badge-degraded' : 'badge-unknown'
              }`}
            >
              {quality.overall_status}
            </span>
          </div>

          <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '14px' }}>
            <HelpCircle size={15} style={{ flexShrink: 0 }} />
            <div>
              <strong>Separation Principle:</strong> Capture fidelity represents observation completeness, not threat severity. Missing telemetry is reported as <code>UNAVAILABLE</code>, never assumed to be 0% loss.
            </div>
          </div>

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Observation Channel</th>
                  <th>Value</th>
                  <th>Status</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {quality.indicators.map((ind, i) => (
                  <tr key={i} title={ind.limitations}>
                    <td style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      {ind.name}
                    </td>
                    <td className="font-mono">
                      {ind.value !== null ? (
                        ind.value
                      ) : (
                        <span style={{ color: 'var(--color-text-muted)' }}>Unavailable</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          ind.status === 'HEALTHY'
                            ? 'badge-healthy'
                            : ind.status === 'DEGRADED'
                            ? 'badge-degraded'
                            : ind.status === 'UNKNOWN'
                            ? 'badge-unknown'
                            : 'badge-unavailable'
                        }`}
                      >
                        {ind.status}
                      </span>
                    </td>
                    <td style={{ color: 'var(--color-text-secondary)', fontSize: '11px' }}>
                      {ind.source}
                    </td>
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
