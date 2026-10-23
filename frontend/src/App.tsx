import React, { useEffect, useState } from 'react'
import type { OverviewData, TimeseriesPoint } from './types'
import { api } from './api'
import { NavigationRail, type TabKey } from './components/NavigationRail'
import { Header } from './components/Header'
import { OverviewView } from './components/OverviewView'
import { FlowsView } from './components/FlowsView'
import { HostGraphView } from './components/HostGraphView'
import { AlertsView } from './components/AlertsView'
import { ReplayLabView } from './components/ReplayLabView'
import { EvaluationView } from './components/EvaluationView'
import { SettingsView } from './components/SettingsView'

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('overview')
  const [overview, setOverview] = useState<OverviewData | null>(null)
  const [timeseries, setTimeseries] = useState<TimeseriesPoint[]>([])
  const [loading, setLoading] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

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
    <div className="workstation-app">
      {/* Navigation Rail */}
      <NavigationRail
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        overview={overview}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      {/* Main Workstation Stage */}
      <div className="workstation-stage">
        {/* Top Header */}
        <Header
          overview={overview}
          loading={loading}
          onRefresh={fetchOverviewData}
          onToggleMobileNav={() => setMobileOpen((prev) => !prev)}
        />

        {/* Analytical Workspace Canvas */}
        <main className="workspace-canvas">
          {activeTab === 'overview' && (
            <OverviewView
              overview={overview}
              timeseries={timeseries}
              onNavigateToAlerts={() => setActiveTab('alerts')}
              onNavigateToFlows={() => setActiveTab('flows')}
              onNavigateToHosts={() => setActiveTab('hosts')}
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
    </div>
  )
}

export default App
