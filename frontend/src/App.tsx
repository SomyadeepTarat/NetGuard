import React, { useEffect, useState } from 'react'
import {
  LayoutDashboard,
  Layers,
  Network,
  AlertTriangle,
  FlaskConical,
  Award,
  Settings
} from 'lucide-react'
import type { OverviewData, TimeseriesPoint } from './types'
import { api } from './api'
import { Header } from './components/Header'
import { OverviewView } from './components/OverviewView'
import { FlowsView } from './components/FlowsView'
import { HostGraphView } from './components/HostGraphView'
import { AlertsView } from './components/AlertsView'
import { ReplayLabView } from './components/ReplayLabView'
import { EvaluationView } from './components/EvaluationView'
import { SettingsView } from './components/SettingsView'

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'flows' | 'hosts' | 'alerts' | 'replay' | 'evaluation' | 'settings'
  >('overview')
  const [overview, setOverview] = useState<OverviewData | null>(null)
  const [timeseries, setTimeseries] = useState<TimeseriesPoint[]>([])
  const [loading, setLoading] = useState(false)

  const fetchOverviewData = async () => {
    setLoading(true)
    try {
      const [ov, ts] = await Promise.all([api.getOverview(), api.getTimeseries()])
      setOverview(ov)
      setTimeseries(ts)
    } catch (e) {
      console.error('Failed to fetch overview telemetry:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOverviewData()
    // Poll every 2 seconds for fresh telemetry
    const interval = setInterval(fetchOverviewData, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="app-container">
      {/* Global Header */}
      <Header overview={overview} loading={loading} onRefresh={fetchOverviewData} />

      {/* Navigation Bar */}
      <nav className="app-nav">
        <button
          className={`nav-tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <LayoutDashboard size={15} /> Overview
        </button>

        <button
          className={`nav-tab ${activeTab === 'flows' ? 'active' : ''}`}
          onClick={() => setActiveTab('flows')}
        >
          <Layers size={15} /> Live Traffic & Flows
          {overview && <span className="nav-count-badge">{overview.active_flows}</span>}
        </button>

        <button
          className={`nav-tab ${activeTab === 'hosts' ? 'active' : ''}`}
          onClick={() => setActiveTab('hosts')}
        >
          <Network size={15} /> Host Explorer
          {overview && <span className="nav-count-badge">{overview.active_hosts}</span>}
        </button>

        <button
          className={`nav-tab ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          <AlertTriangle size={15} /> Alerts & Evidence
          {overview && overview.recent_alerts_count > 0 && (
            <span
              className="nav-count-badge"
              style={{ background: 'var(--accent-rose-bg)', color: 'var(--accent-rose)' }}
            >
              {overview.recent_alerts_count}
            </span>
          )}
        </button>

        <button
          className={`nav-tab ${activeTab === 'replay' ? 'active' : ''}`}
          onClick={() => setActiveTab('replay')}
        >
          <FlaskConical size={15} /> Replay Lab
        </button>

        <button
          className={`nav-tab ${activeTab === 'evaluation' ? 'active' : ''}`}
          onClick={() => setActiveTab('evaluation')}
        >
          <Award size={15} /> Model Evaluation
        </button>

        <button
          className={`nav-tab ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
        >
          <Settings size={15} /> Reports & Settings
        </button>
      </nav>

      {/* Main Content Body */}
      <main className="app-main">
        {activeTab === 'overview' && (
          <OverviewView
            overview={overview}
            timeseries={timeseries}
            onNavigateToAlerts={() => setActiveTab('alerts')}
          />
        )}
        {activeTab === 'flows' && <FlowsView />}
        {activeTab === 'hosts' && <HostGraphView />}
        {activeTab === 'alerts' && <AlertsView />}
        {activeTab === 'replay' && <ReplayLabView />}
        {activeTab === 'evaluation' && <EvaluationView />}
        {activeTab === 'settings' && <SettingsView />}
      </main>
    </div>
  )
}

export default App
