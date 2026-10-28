import React, { useEffect, useState } from 'react'
import {
  Layers,
  Search,
  Filter,
  ArrowRight,
  CheckCircle2,
  X,
  RefreshCw,
  ArrowUpRight,
  ArrowDownLeft,
  Shield,
  Activity
} from 'lucide-react'
import type { FlowRecord } from '../types'
import { api } from '../api'
import { PageHeader } from './PageHeader'

export const FlowsView: React.FC = () => {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [limit, setLimit] = useState(25)
  const [protocol, setProtocol] = useState<string>('')
  const [stateFilter, setStateFilter] = useState<string>('')
  const [search, setSearch] = useState('')
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null)

  const fetchFlows = async () => {
    setLoading(true)
    try {
      const res = await api.getFlows(
        limit,
        page * limit,
        protocol || undefined,
        search || undefined
      )
      // Optional client-side state filtering if needed
      let filtered = res.flows
      if (stateFilter) {
        filtered = filtered.filter((f) => f.state === stateFilter)
      }
      setFlows(filtered)
      setTotal(res.total)
    } catch (e: any) {
      console.error('Failed to fetch flows:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFlows()
  }, [page, limit, protocol, stateFilter, search])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const getProtocolBadgeClass = (proto: string) => {
    switch (proto.toUpperCase()) {
      case 'TCP':
        return 'badge-proto-tcp'
      case 'UDP':
        return 'badge-proto-udp'
      case 'ICMP':
        return 'badge-proto-icmp'
      case 'ARP':
        return 'badge-proto-arp'
      default:
        return 'badge-unavailable'
    }
  }

  const activeFlowsCount = flows.filter((f) => f.state === 'ACTIVE').length

  const handleResetFilters = () => {
    setSearch('')
    setProtocol('')
    setStateFilter('')
    setPage(0)
  }

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Traffic & Flow Aggregation"
        description="Bidirectional flow reconstruction from packet streams with directional metrics and TCP handshake states."
        icon={<Layers size={20} />}
        badge={
          <span className="badge badge-healthy">
            {total} Total Flows ({activeFlowsCount} Active on Page)
          </span>
        }
        actions={
          <button
            className="btn btn-secondary"
            onClick={fetchFlows}
            disabled={loading}
            title="Refresh flow telemetry"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        }
      />

      {/* Filter & Search Toolbar */}
      <div className="card" style={{ padding: '14px 18px', marginBottom: '18px' }}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '14px',
          }}
        >
          {/* Search Input */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              flex: '1',
              minWidth: '260px',
              position: 'relative',
            }}
          >
            <Search
              size={15}
              style={{
                position: 'absolute',
                left: '10px',
                color: 'var(--color-text-muted)',
              }}
            />
            <input
              type="text"
              className="input-text"
              style={{ width: '100%', paddingLeft: '32px' }}
              placeholder="Search by IP endpoint, port, or DNS domain..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{
                  position: 'absolute',
                  right: '10px',
                  background: 'none',
                  border: 'none',
                  color: 'var(--color-text-muted)',
                  cursor: 'pointer',
                }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Controls: Protocol & State & Limit */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              flexWrap: 'wrap',
            }}
          >
            {/* Protocol Pills */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Filter size={13} style={{ color: 'var(--color-text-muted)' }} />
              {['', 'TCP', 'UDP', 'ICMP', 'ARP'].map((p) => {
                const isSelected = protocol === p
                return (
                  <button
                    key={p}
                    className="btn btn-secondary"
                    style={{
                      padding: '4px 9px',
                      fontSize: '11px',
                      fontWeight: 600,
                      background: isSelected ? 'var(--color-accent)' : undefined,
                      borderColor: isSelected ? 'var(--color-accent)' : undefined,
                      color: isSelected ? '#ffffff' : undefined,
                    }}
                    onClick={() => {
                      setProtocol(p)
                      setPage(0)
                    }}
                  >
                    {p || 'ALL'}
                  </button>
                )
              })}
            </div>

            {/* State Filter */}
            <select
              className="select-input"
              value={stateFilter}
              onChange={(e) => {
                setStateFilter(e.target.value)
                setPage(0)
              }}
            >
              <option value="">All States</option>
              <option value="ACTIVE">Active Flows</option>
              <option value="CLOSED">Closed Flows</option>
            </select>

            {/* Limit Selector */}
            <select
              className="select-input"
              value={limit}
              onChange={(e) => {
                setLimit(parseInt(e.target.value, 10))
                setPage(0)
              }}
            >
              <option value="25">25 per page</option>
              <option value="50">50 per page</option>
              <option value="100">100 per page</option>
            </select>
          </div>
        </div>
      </div>

      {/* Flows Data Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Flow Identifier</th>
                <th>Initiator (Client)</th>
                <th style={{ width: '28px', textAlign: 'center' }}></th>
                <th>Responder (Server)</th>
                <th>Protocol</th>
                <th>Packets (↑ / ↓)</th>
                <th>Total Volume</th>
                <th>Duration</th>
                <th>TCP Handshake</th>
                <th>State</th>
                <th style={{ textAlign: 'right' }}>Inspection</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={11} style={{ textAlign: 'center', padding: '48px 20px' }}>
                    {loading ? (
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '10px',
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        <RefreshCw size={24} className="animate-spin" style={{ color: 'var(--color-accent)' }} />
                        <span>Querying bidirectional flow records...</span>
                      </div>
                    ) : (
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '10px',
                        }}
                      >
                        <div
                          style={{
                            width: '40px',
                            height: '40px',
                            borderRadius: '50%',
                            background: 'var(--color-surface-muted)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'var(--color-text-muted)',
                          }}
                        >
                          <Layers size={20} />
                        </div>
                        <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                          No matching network flows
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', maxWidth: '420px' }}>
                          {search || protocol || stateFilter
                            ? 'No flow records match the active search or protocol filter criteria.'
                            : 'No bidirectional flows observed in the current observation session. Start a live capture or trigger a replay in the Replay Lab.'}
                        </div>
                        {(search || protocol || stateFilter) && (
                          <button
                            className="btn btn-secondary"
                            onClick={handleResetFilters}
                            style={{ marginTop: '4px' }}
                          >
                            Reset Filter Criteria
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ) : (
                flows.map((f) => {
                  const isSelected = selectedFlow?.flow_id === f.flow_id
                  return (
                    <tr
                      key={f.flow_id}
                      className={`table-row-clickable ${isSelected ? 'table-row-selected' : ''}`}
                      onClick={() => setSelectedFlow(f)}
                      title="Click to view deep directional metrics in side drawer"
                    >
                      {/* Flow Identifier */}
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-accent)' }}>
                        {f.flow_id}
                      </td>

                      {/* Initiator (Client) */}
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        <span style={{ fontWeight: 500 }}>{f.client_ip}</span>
                        {f.client_port && (
                          <span style={{ color: 'var(--color-text-muted)' }}>:{f.client_port}</span>
                        )}
                      </td>

                      {/* Direction Arrow */}
                      <td style={{ textAlign: 'center', color: 'var(--color-text-muted)' }}>
                        <ArrowRight size={13} />
                      </td>

                      {/* Responder (Server) */}
                      <td style={{ fontFamily: 'var(--font-mono)' }}>
                        <span style={{ fontWeight: 500 }}>{f.server_ip}</span>
                        {f.server_port && (
                          <span style={{ color: 'var(--color-text-muted)' }}>:{f.server_port}</span>
                        )}
                      </td>

                      {/* Protocol */}
                      <td>
                        <span className={`badge ${getProtocolBadgeClass(f.protocol)}`}>
                          {f.protocol}
                        </span>
                      </td>

                      {/* Packets */}
                      <td>
                        <span style={{ fontWeight: 600 }}>{f.packet_count}</span>{' '}
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          ({f.forward_packets}↑ / {f.reverse_packets}↓)
                        </span>
                      </td>

                      {/* Bytes */}
                      <td style={{ fontWeight: 500, fontFamily: 'var(--font-mono)' }}>
                        {formatBytes(f.byte_count)}
                      </td>

                      {/* Duration */}
                      <td style={{ color: 'var(--color-text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        {f.duration.toFixed(2)}s
                      </td>

                      {/* Handshake Facts */}
                      <td>
                        {f.protocol === 'TCP' ? (
                          <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                            {f.handshake.completed ? (
                              <span className="badge badge-healthy" title="Completed 3-way handshake observed">
                                <CheckCircle2 size={11} /> 3WHS
                              </span>
                            ) : f.handshake.syn_observed ? (
                              <span className="badge badge-degraded" title="SYN observed without completed ACK">
                                SYN-ONLY
                              </span>
                            ) : (
                              <span className="badge badge-unknown" title="Midstream observation (no SYN seen)">
                                MIDSTREAM
                              </span>
                            )}
                            {f.handshake.reset_observed && (
                              <span className="badge badge-critical" title="TCP Reset (RST) flag observed">
                                RST
                              </span>
                            )}
                          </div>
                        ) : (
                          <span style={{ color: 'var(--color-text-muted)' }}>-</span>
                        )}
                      </td>

                      {/* State */}
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

                      {/* Inspection Action */}
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '3px 8px', fontSize: '11px' }}
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedFlow(f)
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div
          style={{
            padding: '12px 18px',
            borderTop: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--color-text-secondary)',
            background: 'var(--color-surface)',
          }}
        >
          <div>
            Showing {flows.length} of {total} records (Page {page + 1})
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

      {/* Slide-over Inspection Drawer */}
      {selectedFlow && (
        <div className="slide-drawer-backdrop" onClick={() => setSelectedFlow(null)}>
          <div className="slide-drawer" onClick={(e) => e.stopPropagation()}>
            {/* Drawer Header */}
            <div className="slide-drawer-header">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Layers size={18} style={{ color: 'var(--color-accent)' }} />
                  <h3 style={{ fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                    Flow Inspection
                  </h3>
                  <span className={`badge ${getProtocolBadgeClass(selectedFlow.protocol)}`}>
                    {selectedFlow.protocol}
                  </span>
                  <span
                    className={`badge ${
                      selectedFlow.state === 'ACTIVE' ? 'badge-healthy' : 'badge-unavailable'
                    }`}
                  >
                    {selectedFlow.state}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-text-muted)',
                    marginTop: '4px',
                  }}
                >
                  ID: {selectedFlow.flow_id}
                </div>
              </div>
              <button
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--color-text-secondary)',
                  cursor: 'pointer',
                  padding: '4px',
                }}
                onClick={() => setSelectedFlow(null)}
                aria-label="Close flow drawer"
              >
                <X size={18} />
              </button>
            </div>

            {/* Drawer Content Body */}
            <div className="slide-drawer-body">
              {/* Directional Path Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '14px' }}>
                {/* Forward Path */}
                <div className="stat-box" style={{ padding: '16px' }}>
                  <div className="stat-label">
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <ArrowUpRight size={14} style={{ color: 'var(--color-accent)' }} />
                      Forward Path (Initiator)
                    </span>
                    <span className="badge badge-unavailable">Client</span>
                  </div>
                  <div
                    style={{
                      fontSize: '14px',
                      fontWeight: 600,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-primary)',
                      marginBottom: '6px',
                    }}
                  >
                    {selectedFlow.client_ip}:{selectedFlow.client_port || '-'}
                  </div>
                  <div style={{ display: 'flex', gap: '14px', fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                    <div>
                      <strong>Packets:</strong> {selectedFlow.forward_packets}
                    </div>
                    <div>
                      <strong>Bytes:</strong> {formatBytes(selectedFlow.forward_bytes)}
                    </div>
                  </div>
                  <div
                    style={{
                      marginTop: '10px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border-subtle)',
                      fontSize: '11px',
                      color: 'var(--color-text-secondary)',
                    }}
                  >
                    <span style={{ color: 'var(--color-text-muted)' }}>Observed TCP Flags: </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {selectedFlow.tcp_flags_forward.length > 0
                        ? selectedFlow.tcp_flags_forward.join(', ')
                        : 'None observed'}
                    </span>
                  </div>
                </div>

                {/* Reverse Path */}
                <div className="stat-box" style={{ padding: '16px' }}>
                  <div className="stat-label">
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <ArrowDownLeft size={14} style={{ color: 'var(--color-healthy)' }} />
                      Reverse Path (Responder)
                    </span>
                    <span className="badge badge-unavailable">Server</span>
                  </div>
                  <div
                    style={{
                      fontSize: '14px',
                      fontWeight: 600,
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text-primary)',
                      marginBottom: '6px',
                    }}
                  >
                    {selectedFlow.server_ip}:{selectedFlow.server_port || '-'}
                  </div>
                  <div style={{ display: 'flex', gap: '14px', fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                    <div>
                      <strong>Packets:</strong> {selectedFlow.reverse_packets}
                    </div>
                    <div>
                      <strong>Bytes:</strong> {formatBytes(selectedFlow.reverse_bytes)}
                    </div>
                  </div>
                  <div
                    style={{
                      marginTop: '10px',
                      paddingTop: '8px',
                      borderTop: '1px solid var(--color-border-subtle)',
                      fontSize: '11px',
                      color: 'var(--color-text-secondary)',
                    }}
                  >
                    <span style={{ color: 'var(--color-text-muted)' }}>Observed TCP Flags: </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                      {selectedFlow.tcp_flags_reverse.length > 0
                        ? selectedFlow.tcp_flags_reverse.join(', ')
                        : 'None observed'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Handshake Analysis */}
              {selectedFlow.protocol === 'TCP' && (
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      <Activity size={15} style={{ color: 'var(--color-accent)' }} />
                      TCP Lifecycle Observations
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>3-Way Handshake:</span>
                      <span style={{ fontWeight: 600 }}>
                        {selectedFlow.handshake.completed
                          ? 'Observed & Completed'
                          : selectedFlow.handshake.syn_observed
                          ? 'Incomplete (SYN Only)'
                          : 'Midstream (No SYN Seen)'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>SYN Observed:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {selectedFlow.handshake.syn_observed ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>SYN-ACK Observed:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {selectedFlow.handshake.syn_ack_observed ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>ACK Observed:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {selectedFlow.handshake.ack_observed ? 'Yes' : 'No'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>RST Flag Observed:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: selectedFlow.handshake.reset_observed ? 'var(--color-critical)' : undefined }}>
                        {selectedFlow.handshake.reset_observed ? 'Yes (Connection Terminated)' : 'No'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--color-text-secondary)' }}>Session Duration:</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {selectedFlow.duration.toFixed(3)}s
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Observed DNS Queries */}
              {selectedFlow.dns_queries.length > 0 && (
                <div className="card" style={{ padding: '16px' }}>
                  <div className="card-header" style={{ marginBottom: '10px', paddingBottom: '8px' }}>
                    <div className="card-title" style={{ fontSize: '13px' }}>
                      Correlated DNS Queries
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {selectedFlow.dns_queries.map((q, idx) => (
                      <span
                        key={idx}
                        className="badge badge-unavailable"
                        style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}
                      >
                        {q}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Privacy Boundary Notice */}
              <div className="callout callout-info" style={{ marginTop: 'auto', marginBottom: 0 }}>
                <Shield size={16} style={{ flexShrink: 0 }} />
                <div>
                  <strong>Passive Observability Boundary:</strong> NetGuard operates strictly on packet headers and TCP flag sequences. Application payloads are never inspected, stored, or retained in memory buffers.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default FlowsView
