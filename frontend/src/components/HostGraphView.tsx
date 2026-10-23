import React, { useEffect, useState } from 'react'
import {
  Network,
  Server,
  Laptop,
  Activity,
  RefreshCw,
  Info,
  ArrowUpRight,
  ArrowDownLeft
} from 'lucide-react'
import type { HostGraphData, HostNode, HostEdge } from '../types'
import { api } from '../api'
import { PageHeader } from './PageHeader'

export const HostGraphView: React.FC = () => {
  const [graphData, setGraphData] = useState<HostGraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedHost, setSelectedHost] = useState<HostNode | null>(null)
  const [hoveredEdge, setHoveredEdge] = useState<HostEdge | null>(null)

  const fetchGraph = async () => {
    try {
      const data = await api.getHosts()
      setGraphData(data)
      if (data.nodes.length > 0) {
        // Keep currently selected host if it still exists, otherwise default to first
        setSelectedHost((prev) => {
          if (!prev) return data.nodes[0]
          const exists = data.nodes.find((n) => n.id === prev.id)
          return exists || data.nodes[0]
        })
      } else {
        setSelectedHost(null)
      }
    } catch (e) {
      console.error('Failed to fetch host topology:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchGraph()
    const timer = setInterval(fetchGraph, 4000)
    return () => clearInterval(timer)
  }, [])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const nodes = graphData?.nodes || []
  const edges = graphData?.edges || []

  // Radial positioning for visual communication graph
  const width = 640
  const height = 440
  const centerX = width / 2
  const centerY = height / 2
  const radius = Math.min(centerX, centerY) - 75

  const nodePositions = new Map<string, { x: number; y: number }>()
  nodes.forEach((n, idx) => {
    const angle = (idx / Math.max(nodes.length, 1)) * 2 * Math.PI - Math.PI / 2
    const x = centerX + radius * Math.cos(angle)
    const y = centerY + radius * Math.sin(angle)
    nodePositions.set(n.id, { x, y })
  })

  // Connected edges for the currently selected host
  const selectedHostEdges = selectedHost
    ? edges.filter((e) => e.source === selectedHost.id || e.target === selectedHost.id)
    : []

  const maxTalkerBytes = Math.max(
    ...(graphData?.top_talkers || []).map((t) => t.bytes),
    1
  )

  const getEdgeColor = (proto: string) => {
    switch (proto.toUpperCase()) {
      case 'TCP':
        return '#365cf5'
      case 'UDP':
        return '#0284c7'
      case 'ICMP':
        return '#d97706'
      default:
        return '#8b5cf6'
    }
  }

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Host Communication Explorer"
        description="Observed communication topology and endpoint volume attribution reconstructed from packet traces."
        icon={<Network size={20} />}
        badge={
          <span className="badge badge-healthy">
            {nodes.length} Observed Endpoints | {edges.length} Active Conversations
          </span>
        }
        actions={
          <button
            className="btn btn-secondary"
            onClick={() => {
              setLoading(true)
              fetchGraph()
            }}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Explicit Honesty & Scope Disclaimer */}
      <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '18px' }}>
        <Info size={16} style={{ flexShrink: 0 }} />
        <div>
          <strong>Topology Disclaimer:</strong> {graphData?.disclaimer ||
            'Observed communication graph only. Depicts observed packet exchanges between endpoints; does not infer physical switches, routers, or unobserved topology.'}
        </div>
      </div>

      {nodes.length === 0 ? (
        /* Empty Graph State */
        <div className="card" style={{ textAlign: 'center', padding: '64px 24px' }}>
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
              color: 'var(--color-text-muted)',
            }}
          >
            <Network size={24} />
          </div>
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
            No Endpoint Interactions Observed
          </h3>
          <p
            style={{
              color: 'var(--color-text-secondary)',
              fontSize: '13px',
              maxWidth: '480px',
              margin: '0 auto 16px',
              lineHeight: 1.5,
            }}
          >
            The host explorer maps observed conversations between active IP endpoints. If the packet engine has just started or no packets have arrived yet, endpoint interactions will populate automatically upon packet arrival.
          </p>
          <div style={{ display: 'inline-flex', gap: '8px' }}>
            <button
              className="btn btn-secondary"
              onClick={() => {
                setLoading(true)
                fetchGraph()
              }}
            >
              <RefreshCw size={14} /> Refresh Graph State
            </button>
          </div>
        </div>
      ) : (
        /* Dual-Column Analysis Grid */
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.4fr) minmax(320px, 1fr)',
            gap: '20px',
            alignItems: 'start',
          }}
        >
          {/* Main Visual Communication Graph */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', padding: '20px' }}>
            <div className="card-header" style={{ marginBottom: '12px' }}>
              <div>
                <div className="card-title">
                  <Network size={16} style={{ color: 'var(--color-accent)' }} />
                  Observed Endpoint Interaction Graph
                </div>
                <div className="card-desc">
                  Click any node to inspect conversation endpoints and traffic breakdown.
                </div>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <span className="badge badge-unavailable">{nodes.length} Hosts</span>
                <span className="badge badge-unavailable">{edges.length} Edges</span>
              </div>
            </div>

            {/* SVG Visual Canvas */}
            <div
              style={{
                width: '100%',
                background: 'var(--color-surface-hover)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-border-subtle)',
                position: 'relative',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '10px',
              }}
            >
              <svg
                viewBox={`0 0 ${width} ${height}`}
                style={{ width: '100%', height: 'auto', maxHeight: '480px', overflow: 'visible' }}
              >
                {/* Defs for gradients & filters */}
                <defs>
                  <filter id="nodeShadow" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="2" stdDeviation="2" floodOpacity="0.12" />
                  </filter>
                </defs>

                {/* Graph Edges */}
                {edges.map((e, idx) => {
                  const srcPos = nodePositions.get(e.source)
                  const tgtPos = nodePositions.get(e.target)
                  if (!srcPos || !tgtPos) return null

                  const isConnectedToSelected =
                    selectedHost && (e.source === selectedHost.id || e.target === selectedHost.id)
                  const isHovered = hoveredEdge === e

                  const strokeColor = getEdgeColor(e.protocol)
                  const strokeWidth = Math.min(4, Math.max(1.2, (e.flows || 1) * 1.2))

                  return (
                    <g key={idx}>
                      <line
                        x1={srcPos.x}
                        y1={srcPos.y}
                        x2={tgtPos.x}
                        y2={tgtPos.y}
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        strokeOpacity={
                          isHovered
                            ? 1
                            : isConnectedToSelected
                            ? 0.85
                            : selectedHost
                            ? 0.18
                            : 0.45
                        }
                        strokeDasharray={e.protocol === 'UDP' ? '4 3' : undefined}
                        onMouseEnter={() => setHoveredEdge(e)}
                        onMouseLeave={() => setHoveredEdge(null)}
                        style={{ cursor: 'pointer', transition: 'stroke-opacity 0.15s ease' }}
                      />
                    </g>
                  )
                })}

                {/* Graph Nodes */}
                {nodes.map((n) => {
                  const pos = nodePositions.get(n.id)
                  if (!pos) return null

                  const isSelected = selectedHost?.id === n.id
                  const isServer = n.role === 'server'
                  const nodeRadius = isSelected ? 16 : 13

                  return (
                    <g
                      key={n.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => setSelectedHost(n)}
                      style={{ cursor: 'pointer' }}
                    >
                      {/* Selection outer pulse ring */}
                      {isSelected && (
                        <circle
                          r={nodeRadius + 6}
                          fill="rgba(54, 92, 245, 0.15)"
                          stroke="rgba(54, 92, 245, 0.4)"
                          strokeWidth={1}
                        />
                      )}

                      {/* Main node circle */}
                      <circle
                        r={nodeRadius}
                        fill={
                          isSelected
                            ? 'var(--color-accent)'
                            : isServer
                            ? 'var(--color-healthy)'
                            : '#242c3d'
                        }
                        stroke="#ffffff"
                        strokeWidth={2}
                        filter="url(#nodeShadow)"
                      />

                      {/* Node Center Dot or Role indicator */}
                      <circle
                        r={3}
                        fill="#ffffff"
                      />

                      {/* Endpoint IP Label with background pill */}
                      <g transform={`translate(0, ${nodeRadius + 14})`}>
                        <rect
                          x={-(n.ip.length * 3.4 + 6)}
                          y={-8}
                          width={n.ip.length * 6.8 + 12}
                          height={16}
                          rx={3}
                          fill={isSelected ? '#1e2430' : 'rgba(255, 255, 255, 0.92)'}
                          stroke={isSelected ? 'var(--color-accent)' : 'var(--color-border)'}
                          strokeWidth={0.8}
                        />
                        <text
                          textAnchor="middle"
                          y={3}
                          fill={isSelected ? '#ffffff' : 'var(--color-text-primary)'}
                          fontSize={9.5}
                          fontWeight={isSelected ? 600 : 500}
                          fontFamily="var(--font-mono)"
                        >
                          {n.ip}
                        </text>
                      </g>
                    </g>
                  )
                })}
              </svg>
            </div>

            {/* Edge Hover Tooltip bar */}
            {hoveredEdge && (
              <div
                style={{
                  marginTop: '10px',
                  padding: '6px 12px',
                  background: 'var(--color-surface-muted)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '11.5px',
                  fontFamily: 'var(--font-mono)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <span>
                  <strong>Conversation:</strong> {hoveredEdge.source} ↔ {hoveredEdge.target}
                </span>
                <span>
                  Proto: <strong>{hoveredEdge.protocol}</strong> | Volume: {formatBytes(hoveredEdge.bytes)} ({hoveredEdge.packets} pkts)
                </span>
              </div>
            )}

            {/* Visual Legend */}
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
                marginTop: '14px',
                paddingTop: '12px',
                borderTop: '1px solid var(--color-border-subtle)',
                fontSize: '11px',
                color: 'var(--color-text-secondary)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <span
                    style={{
                      width: '9px',
                      height: '9px',
                      borderRadius: '50%',
                      background: 'var(--color-healthy)',
                      display: 'inline-block',
                    }}
                  />
                  Server Role
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <span
                    style={{
                      width: '9px',
                      height: '9px',
                      borderRadius: '50%',
                      background: '#242c3d',
                      display: 'inline-block',
                    }}
                  />
                  Client / Host Role
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <span
                    style={{
                      width: '9px',
                      height: '9px',
                      borderRadius: '50%',
                      background: 'var(--color-accent)',
                      display: 'inline-block',
                    }}
                  />
                  Selected
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <span
                    style={{
                      width: '14px',
                      height: '2px',
                      background: '#365cf5',
                      display: 'inline-block',
                    }}
                  />
                  TCP
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <span
                    style={{
                      width: '14px',
                      height: '2px',
                      background: '#0284c7',
                      borderTop: '2px dashed #0284c7',
                      display: 'inline-block',
                    }}
                  />
                  UDP
                </span>
                <span style={{ color: 'var(--color-text-muted)' }}>
                  Edge thickness = flow concurrency
                </span>
              </div>
            </div>
          </div>

          {/* Right Inspector Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
            {/* Selected Host Inspector Card */}
            <div className="card">
              <div className="card-header" style={{ marginBottom: '14px' }}>
                <div className="card-title">
                  {selectedHost?.role === 'server' ? (
                    <Server size={16} style={{ color: 'var(--color-healthy)' }} />
                  ) : (
                    <Laptop size={16} style={{ color: 'var(--color-accent)' }} />
                  )}
                  Endpoint Profile
                </div>
                {selectedHost && (
                  <span className="badge badge-unavailable">
                    {selectedHost.role.toUpperCase()}
                  </span>
                )}
              </div>

              {selectedHost ? (
                <div>
                  {/* Host IP Banner */}
                  <div
                    style={{
                      padding: '10px 14px',
                      background: 'var(--color-surface-muted)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: '14px',
                    }}
                  >
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                      OBSERVED ENDPOINT IP
                    </div>
                    <div
                      style={{
                        fontSize: '16px',
                        fontWeight: 700,
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-text-primary)',
                      }}
                    >
                      {selectedHost.ip}
                    </div>
                  </div>

                  {/* Volume Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px' }}>
                    <div className="stat-box" style={{ padding: '12px' }}>
                      <div className="stat-label" style={{ fontSize: '10.5px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ArrowUpRight size={12} /> Outbound
                        </span>
                      </div>
                      <div style={{ fontSize: '14px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                        {formatBytes(selectedHost.sent_bytes)}
                      </div>
                    </div>

                    <div className="stat-box" style={{ padding: '12px' }}>
                      <div className="stat-label" style={{ fontSize: '10.5px' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ArrowDownLeft size={12} /> Inbound
                        </span>
                      </div>
                      <div style={{ fontSize: '14px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                        {formatBytes(selectedHost.recv_bytes)}
                      </div>
                    </div>
                  </div>

                  {/* Concurrent Flows Metric */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      background: 'var(--color-surface-hover)',
                      border: '1px solid var(--color-border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: '14px',
                    }}
                  >
                    <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                      Active Concurrent Flows:
                    </span>
                    <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                      {selectedHost.flows} sessions
                    </span>
                  </div>

                  {/* Connected Conversations */}
                  <div>
                    <div
                      style={{
                        fontSize: '11.5px',
                        fontWeight: 600,
                        color: 'var(--color-text-secondary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                        marginBottom: '8px',
                      }}
                    >
                      Active Conversations ({selectedHostEdges.length})
                    </div>
                    {selectedHostEdges.length === 0 ? (
                      <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        No conversations recorded for this endpoint in current window.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {selectedHostEdges.map((e, idx) => {
                          const peerIp = e.source === selectedHost.id ? e.target : e.source
                          return (
                            <div
                              key={idx}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                padding: '6px 10px',
                                background: 'var(--color-surface-hover)',
                                border: '1px solid var(--color-border-subtle)',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: '12px',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span className={`badge ${e.protocol === 'TCP' ? 'badge-proto-tcp' : 'badge-proto-udp'}`}>
                                  {e.protocol}
                                </span>
                                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
                                  {peerIp}
                                </span>
                              </div>
                              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', fontSize: '11px' }}>
                                {formatBytes(e.bytes)}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--color-text-muted)', fontSize: '12px', textAlign: 'center', padding: '24px 0' }}>
                  Select an endpoint node in the graph to view traffic volume and active conversations.
                </div>
              )}
            </div>

            {/* Observed Top Talkers Leaderboard */}
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
                  <Activity size={15} style={{ color: 'var(--color-accent)' }} />
                  Observed Top Talkers
                </div>
                <span className="badge badge-unavailable">
                  {(graphData?.top_talkers || []).length} Endpoints
                </span>
              </div>

              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: '40px' }}>Rank</th>
                      <th>Host IP</th>
                      <th style={{ textAlign: 'right' }}>Total Volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(graphData?.top_talkers || []).length === 0 ? (
                      <tr>
                        <td colSpan={3} style={{ textAlign: 'center', padding: '20px', color: 'var(--color-text-muted)' }}>
                          No conversation traffic recorded yet.
                        </td>
                      </tr>
                    ) : (
                      (graphData?.top_talkers || []).map((t, idx) => {
                        const isSelected = selectedHost?.ip === t.ip
                        const percentage = ((t.bytes / maxTalkerBytes) * 100).toFixed(0)
                        return (
                          <tr
                            key={idx}
                            className={`table-row-clickable ${isSelected ? 'table-row-selected' : ''}`}
                            onClick={() => {
                              const match = nodes.find((n) => n.ip === t.ip)
                              if (match) setSelectedHost(match)
                            }}
                          >
                            <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)', fontSize: '11px' }}>
                              #{idx + 1}
                            </td>
                            <td>
                              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{t.ip}</div>
                              {/* Relative volume progress bar */}
                              <div
                                style={{
                                  width: '100%',
                                  height: '3px',
                                  background: 'var(--color-border-subtle)',
                                  borderRadius: '2px',
                                  marginTop: '4px',
                                  overflow: 'hidden',
                                }}
                              >
                                <div
                                  style={{
                                    width: `${percentage}%`,
                                    height: '100%',
                                    background: isSelected ? 'var(--color-accent)' : 'var(--color-healthy)',
                                    borderRadius: '2px',
                                  }}
                                />
                              </div>
                            </td>
                            <td style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                              {formatBytes(t.bytes)}
                            </td>
                          </tr>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default HostGraphView
