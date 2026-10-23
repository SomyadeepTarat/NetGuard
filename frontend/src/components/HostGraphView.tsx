import React, { useEffect, useState } from 'react'
import { Network, AlertCircle, Server, Laptop, Activity } from 'lucide-react'
import type { HostGraphData, HostNode } from '../types'
import { api } from '../api'

export const HostGraphView: React.FC = () => {
  const [graphData, setGraphData] = useState<HostGraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedHost, setSelectedHost] = useState<HostNode | null>(null)

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const data = await api.getHosts()
        setGraphData(data)
        if (data.nodes.length > 0 && !selectedHost) {
          setSelectedHost(data.nodes[0])
        }
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    fetchGraph()
    const timer = setInterval(fetchGraph, 5000)
    return () => clearInterval(timer)
  }, [])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  if (loading && !graphData) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
        <Network size={32} className="animate-spin" style={{ margin: '0 auto 12px', color: 'var(--accent-cyan)' }} />
        <div style={{ color: 'var(--text-secondary)' }}>Building observed communication graph...</div>
      </div>
    )
  }

  const nodes = graphData?.nodes || []
  const edges = graphData?.edges || []

  // Radial positioning for visual communication graph
  const width = 600
  const height = 400
  const centerX = width / 2
  const centerY = height / 2
  const radius = 140

  const nodePositions = new Map<string, { x: number; y: number }>()
  nodes.forEach((n, idx) => {
    const angle = (idx / Math.max(nodes.length, 1)) * 2 * Math.PI
    const x = centerX + radius * Math.cos(angle)
    const y = centerY + radius * Math.sin(angle)
    nodePositions.set(n.id, { x, y })
  })

  return (
    <div>
      {/* Explicit Honesty Disclaimer */}
      <div className="callout callout-info" style={{ marginTop: 0, marginBottom: '16px' }}>
        <AlertCircle size={16} style={{ flexShrink: 0 }} />
        <div>
          <strong>Topology Disclaimer:</strong> {graphData?.disclaimer || 'Observed communication graph only. Depicts observed packet exchanges; does not infer physical switches, routers, or unobserved topology.'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '18px' }}>
        {/* Interactive Visual Graph Canvas */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-header">
            <div className="card-title">
              <Network size={16} style={{ color: 'var(--accent-cyan)' }} />
              Observed Endpoint Communication Relationships
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              {nodes.length} hosts | {edges.length} connections
            </div>
          </div>

          <div style={{ flex: 1, minHeight: '380px', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
            <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: '100%', maxWidth: '600px' }}>
              {/* Communication Links */}
              {edges.map((e, idx) => {
                const srcPos = nodePositions.get(e.source)
                const tgtPos = nodePositions.get(e.target)
                if (!srcPos || !tgtPos) return null
                return (
                  <line
                    key={idx}
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke="#1e293b"
                    strokeWidth={Math.min(4, Math.max(1, e.flows))}
                    strokeOpacity={0.6}
                  />
                )
              })}

              {/* Endpoint Nodes */}
              {nodes.map((n) => {
                const pos = nodePositions.get(n.id)
                if (!pos) return null
                const isSelected = selectedHost?.id === n.id
                return (
                  <g
                    key={n.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={() => setSelectedHost(n)}
                    style={{ cursor: 'pointer' }}
                  >
                    <circle
                      r={isSelected ? 16 : 12}
                      fill={isSelected ? '#06b6d4' : '#0f172a'}
                      stroke={isSelected ? '#22d3ee' : '#334155'}
                      strokeWidth={2}
                    />
                    <text
                      y={26}
                      textAnchor="middle"
                      fill={isSelected ? '#f8fafc' : '#94a3b8'}
                      fontSize={10}
                      fontFamily="var(--font-mono)"
                    >
                      {n.ip}
                    </text>
                  </g>
                )
              })}
            </svg>
          </div>
        </div>

        {/* Selected Host Details & Top Talkers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Host Inspector */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                {selectedHost?.role === 'server' ? <Server size={16} /> : <Laptop size={16} />}
                Endpoint Profile: {selectedHost?.ip || 'None selected'}
              </div>
              <span className="badge badge-unavailable">{selectedHost?.role?.toUpperCase() || 'HOST'}</span>
            </div>

            {selectedHost ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="stat-box">
                  <div className="stat-label">Outbound Transmission</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {formatBytes(selectedHost.sent_bytes)}
                  </div>
                </div>
                <div className="stat-box">
                  <div className="stat-label">Inbound Reception</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {formatBytes(selectedHost.recv_bytes)}
                  </div>
                </div>
                <div className="stat-box" style={{ gridColumn: 'span 2' }}>
                  <div className="stat-label">Associated Concurrent Flows</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                    {selectedHost.flows} active sessions
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Select an endpoint to inspect traffic metrics.</div>
            )}
          </div>

          {/* Top Talkers Leaderboard */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Activity size={16} style={{ color: 'var(--accent-cyan)' }} />
                Observed Top Talkers
              </div>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Host IP</th>
                    <th>Volume</th>
                  </tr>
                </thead>
                <tbody>
                  {(graphData?.top_talkers || []).map((t, idx) => (
                    <tr key={idx}>
                      <td style={{ color: 'var(--text-primary)' }}>{t.ip}</td>
                      <td>{formatBytes(t.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
