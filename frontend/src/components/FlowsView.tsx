import React, { useEffect, useState } from 'react'
import { Filter, Search, ArrowRight, CheckCircle2, Info, X } from 'lucide-react'
import type { FlowRecord } from '../types'
import { api } from '../api'

export const FlowsView: React.FC = () => {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [limit] = useState(25)
  const [protocol, setProtocol] = useState<string>('')
  const [search, setSearch] = useState('')
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null)

  const fetchFlows = async () => {
    setLoading(true)
    try {
      const res = await api.getFlows(limit, page * limit, protocol || undefined, search || undefined)
      setFlows(res.flows)
      setTotal(res.total)
    } catch (e: any) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFlows()
  }, [page, protocol, search])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <div>
      {/* Search & Filter Bar */}
      <div className="card" style={{ padding: '14px 18px', marginBottom: '14px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: '1', minWidth: '240px' }}>
            <Search size={16} style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="input-text"
              style={{ width: '100%', maxWidth: '360px' }}
              placeholder="Search by IP, port, or DNS domain..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={14} style={{ color: 'var(--text-muted)' }} />
            {['', 'TCP', 'UDP', 'ICMP', 'ARP'].map((p) => (
              <button
                key={p}
                className="btn btn-secondary"
                style={{
                  padding: '4px 10px',
                  fontSize: '11px',
                  background: protocol === p ? 'var(--accent-cyan-bg)' : undefined,
                  borderColor: protocol === p ? 'var(--accent-cyan-border)' : undefined,
                  color: protocol === p ? 'var(--accent-cyan)' : undefined,
                }}
                onClick={() => {
                  setProtocol(p)
                  setPage(0)
                }}
              >
                {p || 'ALL'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Flows Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Flow Identifier</th>
                <th>Initiator (Client)</th>
                <th>Direction</th>
                <th>Responder (Server)</th>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Duration</th>
                <th>Handshake Facts</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                    {loading ? 'Loading active flows...' : 'No flows match the active filter criteria.'}
                  </td>
                </tr>
              ) : (
                flows.map((f) => (
                  <tr
                    key={f.flow_id}
                    className="table-row-clickable"
                    onClick={() => setSelectedFlow(f)}
                    title="Click to view deep directional metrics"
                  >
                    <td style={{ color: 'var(--accent-cyan)' }}>{f.flow_id}</td>
                    <td>
                      {f.client_ip}
                      {f.client_port ? `:${f.client_port}` : ''}
                    </td>
                    <td style={{ color: 'var(--text-muted)' }}>
                      <ArrowRight size={12} />
                    </td>
                    <td>
                      {f.server_ip}
                      {f.server_port ? `:${f.server_port}` : ''}
                    </td>
                    <td>
                      <span className="badge badge-unavailable">{f.protocol}</span>
                    </td>
                    <td>
                      {f.packet_count} <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>({f.forward_packets}↑ / {f.reverse_packets}↓)</span>
                    </td>
                    <td>{formatBytes(f.byte_count)}</td>
                    <td>{f.duration.toFixed(2)}s</td>
                    <td>
                      {f.protocol === 'TCP' ? (
                        <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                          {f.handshake.completed ? (
                            <span className="badge badge-healthy" title="Completed 3-way handshake observed">
                              <CheckCircle2 size={10} /> 3WHS
                            </span>
                          ) : f.handshake.syn_observed ? (
                            <span className="badge badge-unknown" title="SYN observed without completed ACK">
                              SYN-ONLY
                            </span>
                          ) : (
                            <span className="badge badge-unavailable">MIDSTREAM</span>
                          )}
                          {f.handshake.reset_observed && (
                            <span className="badge badge-degraded" title="TCP Reset RST observed">
                              RST
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>-</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          f.state === 'ACTIVE'
                            ? 'badge-healthy'
                            : f.state === 'CLOSED'
                            ? 'badge-unavailable'
                            : 'badge-unknown'
                        }`}
                      >
                        {f.state}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div
          style={{
            padding: '12px 18px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--text-secondary)',
          }}
        >
          <div>
            Showing {flows.length} of {total} flows
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn btn-secondary"
              disabled={page === 0 || loading}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <button
              className="btn btn-secondary"
              disabled={(page + 1) * limit >= total || loading}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Flow Details Modal */}
      {selectedFlow && (
        <div className="modal-overlay" onClick={() => setSelectedFlow(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '600px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Flow Inspection: {selectedFlow.flow_id}
              </h3>
              <button
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                onClick={() => setSelectedFlow(null)}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginBottom: '16px' }}>
              <div className="stat-box">
                <div className="stat-label">Forward Path (Initiator)</div>
                <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                  {selectedFlow.client_ip}:{selectedFlow.client_port || '-'}
                </div>
                <div className="stat-sub">
                  {selectedFlow.forward_packets} packets | {formatBytes(selectedFlow.forward_bytes)}
                </div>
                <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  Flags: {selectedFlow.tcp_flags_forward.join(', ') || 'None'}
                </div>
              </div>

              <div className="stat-box">
                <div className="stat-label">Reverse Path (Responder)</div>
                <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
                  {selectedFlow.server_ip}:{selectedFlow.server_port || '-'}
                </div>
                <div className="stat-sub">
                  {selectedFlow.reverse_packets} packets | {formatBytes(selectedFlow.reverse_bytes)}
                </div>
                <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  Flags: {selectedFlow.tcp_flags_reverse.join(', ') || 'None'}
                </div>
              </div>
            </div>

            {selectedFlow.dns_queries.length > 0 && (
              <div style={{ marginBottom: '14px' }}>
                <div className="stat-label">Observed DNS Queries</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                  {selectedFlow.dns_queries.map((q, idx) => (
                    <span key={idx} className="badge badge-unavailable">
                      {q}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="callout callout-info">
              <Info size={16} />
              <div>
                <strong>Privacy Boundary:</strong> Metadata only. NetGuard does not buffer or retain application payloads. Handshake facts are derived strictly from observed TCP flag sequence.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
