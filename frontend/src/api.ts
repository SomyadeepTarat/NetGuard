import type {
  HealthResponse,
  OverviewData,
  TimeseriesPoint,
  FlowRecord,
  HostGraphData,
  EvidencePassport,
  ReplayExperiment,
  PcapFileInfo,
  EvaluationData,
  RobustnessSweepRun,
  ObservationPlan,
  LineageVerifyResult,
  LineageEvent,
  EvidenceBundle,
} from './types'

const API_BASE = '/api'

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })
  if (!res.ok) {
    let errorDetail = `Request failed (${res.status} ${res.statusText})`
    try {
      const json = await res.json()
      if (json.detail) errorDetail = json.detail
    } catch {}
    throw new Error(errorDetail)
  }
  return res.json() as Promise<T>
}

export const api = {
  getHealth: () => request<HealthResponse>('/health'),
  getOverview: () => request<OverviewData>('/overview'),
  getTimeseries: () => request<TimeseriesPoint[]>('/traffic/timeseries'),
  getInterfaces: () => request<Array<{ name: string; description: string; ip: string; is_default: boolean }>>('/interfaces'),
  
  startCapture: (mode: string, iface?: string, pcap?: string, filter?: string) =>
    request<{ status: string; mode: string; interface: string }>('/capture/start', {
      method: 'POST',
      body: JSON.stringify({ mode, interface: iface, pcap_path: pcap, capture_filter: filter }),
    }),

  stopCapture: () =>
    request<{ status: string; mode: string; interface: string }>('/capture/stop', { method: 'POST' }),

  getFlows: (limit = 50, offset = 0, protocol?: string, search?: string) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (protocol) params.set('protocol', protocol)
    if (search) params.set('search', search)
    return request<{ total: number; limit: number; offset: number; flows: FlowRecord[] }>(`/flows?${params}`)
  },

  getFlow: (flowId: string) => request<FlowRecord>(`/flows/${flowId}`),

  getHosts: () => request<HostGraphData>('/hosts'),

  getAlerts: (limit = 50, offset = 0, classFilter?: string, severityFilter?: string, search?: string, redactIps = false) => {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      redact_ips: String(redactIps),
    })
    if (classFilter) params.set('class_filter', classFilter)
    if (severityFilter) params.set('severity_filter', severityFilter)
    if (search) params.set('search', search)
    return request<{ total: number; limit: number; offset: number; alerts: EvidencePassport[] }>(`/alerts?${params}`)
  },

  getAlertPassport: (alertId: string, redactIps = false) =>
    request<EvidencePassport>(`/alerts/${alertId}?redact_ips=${redactIps}`),

  getAvailablePcaps: () => request<PcapFileInfo[]>('/replays/pcaps'),

  createReplay: (params: {
    pcap_path: string
    loss_mode: 'random' | 'burst' | 'directional'
    drop_rate: number
    seed: number
    burst_size?: number
    burst_interval?: number
    drop_ip?: string
  }) => request<ReplayExperiment>('/replays', { method: 'POST', body: JSON.stringify(params) }),

  getReplay: (runId: string) => request<ReplayExperiment>(`/replays/${runId}`),
  listReplays: () => request<ReplayExperiment[]>('/replays'),
  cancelReplay: (runId: string) => request<{ status: string; run_id: string }>(`/replays/${runId}/cancel`, { method: 'POST' }),

  getEvaluation: () => request<EvaluationData>('/evaluation'),
  getFusionEvaluation: () => request<{
    status: string
    report?: { scope: string; runs: Array<{ results: Array<{ method: string; tp: number; fp: number; fn: number; tn: number; abstentions: number }> }> }
  }>('/detection/evaluation'),
  getSettings: () => request<any>('/settings'),

  // ============================================================================
  // Lens / Evidence Resilience Engine (ERE) API
  // ============================================================================
  createRobustnessSweep: (params: {
    pcap_path: string
    loss_modes?: string[]
    drop_rates?: number[]
    seeds?: number[]
    burst_configs?: Array<[number, number]>
    drop_ips?: string[]
    max_runs?: number
  }) => request<RobustnessSweepRun>('/lens/robustness-runs', {
    method: 'POST',
    body: JSON.stringify(params),
  }),

  listRobustnessSweeps: () => request<RobustnessSweepRun[]>('/lens/robustness-runs'),
  getRobustnessSweep: (runId: string) => request<RobustnessSweepRun>(`/lens/robustness-runs/${runId}`),
  cancelRobustnessSweep: (runId: string) =>
    request<{ status: string; run_id: string }>(`/lens/robustness-runs/${runId}/cancel`, { method: 'POST' }),
  getRobustnessSweepReport: (runId: string) => request<any>(`/lens/robustness-runs/${runId}/report`),

  getAlertObservationPlan: (alertId: string, runId?: string) => {
    const q = runId ? `?run_id=${encodeURIComponent(runId)}` : ''
    return request<ObservationPlan>(`/lens/alerts/${alertId}/observation-plan${q}`)
  },

  verifyLineage: () => request<LineageVerifyResult>('/lens/lineage/verify'),
  listLineageEvents: (limit = 50, offset = 0) =>
    request<{ events: LineageEvent[]; total: number; limit: number; offset: number }>(
      `/lens/lineage/events?limit=${limit}&offset=${offset}`
    ),
  getLineageEvent: (eventId: string) => request<LineageEvent>(`/lens/lineage/${eventId}`),
  getEvidenceBundle: (runOrEventId: string) =>
    request<EvidenceBundle>(`/lens/evidence-bundle/${encodeURIComponent(runOrEventId)}`),
}
