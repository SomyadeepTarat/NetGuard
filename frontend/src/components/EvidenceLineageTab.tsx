import React, { useState, useEffect } from 'react'
import {
  Link2,
  Download,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  FileCode
} from 'lucide-react'
import type { LineageEvent, LineageVerifyResult } from '../types'
import { api } from '../api'

export const EvidenceLineageTab: React.FC = () => {
  const [events, setEvents] = useState<LineageEvent[]>([])
  const [totalEvents, setTotalEvents] = useState(0)
  const [selectedEvent, setSelectedEvent] = useState<LineageEvent | null>(null)
  const [verification, setVerification] = useState<LineageVerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [copiedDigest, setCopiedDigest] = useState(false)
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    loadLineageData()
  }, [])

  const loadLineageData = async () => {
    try {
      const res = await api.listLineageEvents(50, 0)
      setEvents(res.events)
      setTotalEvents(res.total)
      if (res.events.length > 0 && !selectedEvent) {
        setSelectedEvent(res.events[0])
      }
      runVerification()
    } catch (e: any) {
      console.error('Failed to load lineage events:', e)
    }
  }

  const runVerification = async () => {
    setVerifying(true)
    try {
      const result = await api.verifyLineage()
      setVerification(result)
    } catch (e: any) {
      console.error('Verification failed:', e)
    } finally {
      setVerifying(false)
    }
  }

  const handleCopyDigest = (digest: string) => {
    navigator.clipboard.writeText(digest)
    setCopiedDigest(true)
    setTimeout(() => setCopiedDigest(false), 2000)
  }

  const handleExportBundle = async () => {
    if (!selectedEvent) return
    setExporting(true)
    try {
      const bundle = await api.getEvidenceBundle(selectedEvent.event_id)
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(bundle, null, 2))
      const downloadAnchor = document.createElement('a')
      downloadAnchor.setAttribute('href', dataStr)
      downloadAnchor.setAttribute('download', `netguard_evidence_bundle_${selectedEvent.event_id}.json`)
      document.body.appendChild(downloadAnchor)
      downloadAnchor.click()
      downloadAnchor.remove()
    } catch (e: any) {
      alert(`Bundle export failed: ${e.message}`)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 480px', gap: '24px', alignItems: 'start' }}>
      {/* Left Column: Chain Status & Event Log */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {/* Verification Summary Card */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Link2 size={18} style={{ color: 'var(--color-accent)' }} />
              <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Cryptographic Evidence Hash Chain
              </h2>
            </div>
            <button
              type="button"
              className="btn btn-outline"
              onClick={runVerification}
              disabled={verifying}
              style={{ fontSize: '11.5px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <RefreshCw size={13} className={verifying ? 'spin' : ''} />
              Recompute & Verify Chain
            </button>
          </div>

          {/* Verification Status Banner */}
          {verification && (
            <div
              style={{
                background:
                  verification.status === 'VALID'
                    ? 'var(--color-healthy-bg)'
                    : verification.status === 'INVALID'
                    ? 'var(--color-critical-bg)'
                    : 'var(--color-unknown-bg)',
                border: `1px solid ${
                  verification.status === 'VALID'
                    ? 'var(--color-healthy-border)'
                    : verification.status === 'INVALID'
                    ? 'var(--color-critical-border)'
                    : 'var(--color-unknown-border)'
                }`,
                borderRadius: 'var(--radius-md)',
                padding: '14px 18px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <div>
                <div style={{
                  fontSize: '14px',
                  fontWeight: 700,
                  color:
                    verification.status === 'VALID'
                      ? 'var(--color-healthy)'
                      : verification.status === 'INVALID'
                      ? 'var(--color-critical)'
                      : 'var(--color-unknown)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  {verification.status === 'VALID' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                  CHAIN VERIFICATION: {verification.status}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                  {verification.message || verification.error_reason}
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Verified Blocks</div>
                <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                  {verification.events_count}
                </div>
              </div>
            </div>
          )}

          {/* Security & Boundary Notice */}
          <div style={{
            marginTop: '14px',
            fontSize: '11.5px',
            color: 'var(--color-text-muted)',
            lineHeight: 1.4,
            borderTop: '1px solid var(--color-border)',
            paddingTop: '12px'
          }}>
            <strong>Threat Boundary Disclaimer:</strong> SHA-256 hash chains guarantee tamper evidence against in-place modifications within application storage. They do not prevent database destruction or hostile administrator database overwrite.
          </div>
        </div>

        {/* Append-Only Event Log */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Append-Only Lineage Events ({totalEvents})
            </h3>
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
              RFC 8785 Canonical JSON Manifests
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '480px', overflowY: 'auto' }}>
            {events.map((evt) => {
              const isSelected = selectedEvent?.event_id === evt.event_id
              return (
                <div
                  key={evt.event_id}
                  onClick={() => setSelectedEvent(evt)}
                  style={{
                    padding: '12px',
                    borderRadius: 'var(--radius-sm)',
                    border: isSelected ? '1px solid var(--color-accent)' : '1px solid var(--color-border)',
                    background: isSelected ? 'var(--color-surface-hover)' : 'var(--color-surface)',
                    cursor: 'pointer',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                      <span
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: 'var(--radius-sm)',
                          background: 'var(--color-surface-muted)',
                          fontFamily: 'var(--font-mono)'
                        }}
                      >
                        #{evt.sequence_id}
                      </span>
                      <span style={{ fontSize: '12.5px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                        {evt.event_type}
                      </span>
                      {evt.parent_id && (
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          parent: {evt.parent_id}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Hash: {evt.event_hash.slice(0, 16)}... • {evt.iso_time}
                    </div>
                  </div>

                  <span className="badge badge-subtle" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {evt.event_id}
                  </span>
                </div>
              )
            })}

            {events.length === 0 && (
              <div style={{ textAlign: 'center', padding: '30px', color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
                No lineage events recorded yet. Run a robustness sweep or record an incident to build the hash chain.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Column: Manifest Inspector & Evidence Bundle Export */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {selectedEvent ? (
          <div className="card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Manifest Inspector: #{selectedEvent.sequence_id}
                </h3>
                <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {selectedEvent.event_id}
                </div>
              </div>

              <button
                type="button"
                className="btn btn-primary"
                onClick={handleExportBundle}
                disabled={exporting}
                style={{ fontSize: '11.5px', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Download size={13} /> Export Evidence Bundle
              </button>
            </div>

            {/* Hash Continuity Badges */}
            <div style={{
              background: 'var(--color-surface-hover)',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              marginBottom: '14px',
              fontSize: '11.5px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}>
              <div>
                <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>Manifest SHA-256 Digest:</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '11px', marginTop: '2px' }}>
                  <span style={{ wordBreak: 'break-all' }}>{selectedEvent.manifest_digest}</span>
                  <button
                    type="button"
                    onClick={() => handleCopyDigest(selectedEvent.manifest_digest)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-accent)' }}
                    title="Copy manifest digest"
                  >
                    <Copy size={13} />
                  </button>
                  {copiedDigest && <span style={{ color: 'var(--color-healthy)', fontSize: '10px' }}>Copied</span>}
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>Previous Block Hash:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all', marginTop: '2px' }}>
                  {selectedEvent.previous_hash}
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>Block Event Hash:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', wordBreak: 'break-all', marginTop: '2px', color: 'var(--color-accent)' }}>
                  {selectedEvent.event_hash}
                </div>
              </div>
            </div>

            {/* Manifest JSON Viewer */}
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '6px' }}>
                Canonical Manifest Payload
              </div>
              <pre
                style={{
                  background: 'var(--color-surface-sunken)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '12px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-text-primary)',
                  maxHeight: '400px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all'
                }}
              >
                {JSON.stringify(selectedEvent.manifest, null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <div className="card" style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileCode size={36} style={{ color: 'var(--color-text-muted)', margin: '0 auto 16px' }} />
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '6px' }}>
              No Lineage Event Selected
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)', maxWidth: '320px', margin: '0 auto' }}>
              Select an append-only block on the left to inspect its canonical manifest digest and download its evidence bundle.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
