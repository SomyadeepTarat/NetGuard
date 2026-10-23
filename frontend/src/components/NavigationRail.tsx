import React from 'react'
import {
  LayoutDashboard,
  Layers,
  Network,
  AlertTriangle,
  FlaskConical,
  Award,
  Settings,
  Shield,
  X
} from 'lucide-react'
import type { OverviewData } from '../types'

export type TabKey = 'overview' | 'flows' | 'hosts' | 'alerts' | 'replay' | 'evaluation' | 'settings'

interface NavigationRailProps {
  activeTab: TabKey
  onSelectTab: (tab: TabKey) => void
  overview: OverviewData | null
  mobileOpen: boolean
  onCloseMobile: () => void
}

export const NavigationRail: React.FC<NavigationRailProps> = ({
  activeTab,
  onSelectTab,
  overview,
  mobileOpen,
  onCloseMobile,
}) => {
  const isCapturing = overview?.status === 'CAPTURING'
  const mode = overview?.mode || 'DEMO'

  const handleNav = (tab: TabKey) => {
    onSelectTab(tab)
    if (mobileOpen) {
      onCloseMobile()
    }
  }

  // Format uptime
  const formatUptime = (seconds: number) => {
    if (seconds < 60) return `${Math.floor(seconds)}s`
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    if (mins < 60) return `${mins}m ${secs}s`
    const hrs = Math.floor(mins / 60)
    return `${hrs}h ${mins % 60}m`
  }

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(10, 14, 22, 0.65)',
            backdropFilter: 'blur(3px)',
            zIndex: 49,
          }}
          onClick={onCloseMobile}
        />
      )}

      <aside className={`workstation-rail ${mobileOpen ? 'mobile-open' : ''}`}>
        {/* Brand Section */}
        <div className="rail-brand">
          <div className="rail-logo-badge">
            <Shield size={18} strokeWidth={2.5} />
          </div>
          <div className="rail-brand-meta">
            <div className="rail-brand-title">
              <span>NETGUARD</span>
              <span className="rail-brand-version">v1.2</span>
            </div>
            <div className="rail-brand-sub">Threat Observatory</div>
          </div>
          {mobileOpen && (
            <button
              style={{
                marginLeft: 'auto',
                background: 'transparent',
                border: 'none',
                color: 'var(--color-shell-muted)',
                cursor: 'pointer',
              }}
              onClick={onCloseMobile}
              aria-label="Close menu"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Categorized Navigation Groups */}
        <nav className="rail-nav">
          {/* OBSERVE */}
          <div className="rail-group">
            <div className="rail-group-label">Observe</div>

            <button
              className={`rail-item ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => handleNav('overview')}
            >
              <div className="rail-item-left">
                <LayoutDashboard size={16} />
                <span>Overview</span>
              </div>
            </button>

            <button
              className={`rail-item ${activeTab === 'flows' ? 'active' : ''}`}
              onClick={() => handleNav('flows')}
            >
              <div className="rail-item-left">
                <Layers size={16} />
                <span>Traffic & Flows</span>
              </div>
              {overview && (
                <span className="rail-badge">{overview.active_flows}</span>
              )}
            </button>

            <button
              className={`rail-item ${activeTab === 'hosts' ? 'active' : ''}`}
              onClick={() => handleNav('hosts')}
            >
              <div className="rail-item-left">
                <Network size={16} />
                <span>Host Explorer</span>
              </div>
              {overview && (
                <span className="rail-badge">{overview.active_hosts}</span>
              )}
            </button>
          </div>

          {/* INVESTIGATE */}
          <div className="rail-group">
            <div className="rail-group-label">Investigate</div>

            <button
              className={`rail-item ${activeTab === 'alerts' ? 'active' : ''}`}
              onClick={() => handleNav('alerts')}
            >
              <div className="rail-item-left">
                <AlertTriangle size={16} />
                <span>Alerts & Evidence</span>
              </div>
              {overview && overview.recent_alerts_count > 0 && (
                <span className="rail-badge rail-badge-alert">
                  {overview.recent_alerts_count}
                </span>
              )}
            </button>

            <button
              className={`rail-item ${activeTab === 'replay' ? 'active' : ''}`}
              onClick={() => handleNav('replay')}
            >
              <div className="rail-item-left">
                <FlaskConical size={16} />
                <span>Replay Lab</span>
              </div>
            </button>

            <button
              className={`rail-item ${activeTab === 'evaluation' ? 'active' : ''}`}
              onClick={() => handleNav('evaluation')}
            >
              <div className="rail-item-left">
                <Award size={16} />
                <span>Model Evaluation</span>
              </div>
            </button>
          </div>

          {/* AUDIT & REPORT */}
          <div className="rail-group">
            <div className="rail-group-label">Audit & Report</div>

            <button
              className={`rail-item ${activeTab === 'settings' ? 'active' : ''}`}
              onClick={() => handleNav('settings')}
            >
              <div className="rail-item-left">
                <Settings size={16} />
                <span>Reports & Settings</span>
              </div>
            </button>
          </div>
        </nav>

        {/* Rail Footer & Ingestion Health */}
        <div className="rail-footer">
          <div className="session-status-pill">
            <div className="session-status-tag">
              <span
                className={`status-dot ${isCapturing ? 'active' : 'stopped'}`}
              />
              <span style={{ color: 'var(--color-shell-text)' }}>
                {isCapturing ? 'INGESTING' : 'STOPPED'}
              </span>
            </div>
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--color-shell-muted)',
              }}
            >
              {overview ? formatUptime(overview.uptime_seconds) : '0s'}
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '10.5px',
              color: 'var(--color-shell-muted)',
              padding: '0 4px',
            }}
          >
            <span>Telemetry Source</span>
            <span className="font-mono" style={{ color: '#cbd5e1' }}>
              {mode}
            </span>
          </div>
        </div>
      </aside>
    </>
  )
}
