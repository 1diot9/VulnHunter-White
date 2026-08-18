export type WeightExt = {
  ext: string
  agent_added: boolean
  files: number
}

export type Project = {
  id: number
  name: string
  source_type: string
  source_url: string | null
  identity: string | null
  status: string
  phase: string
  recon_done: boolean
  audit_mode: 'bounty' | 'full'
  manual_lab: boolean
  manual_lab_prompt: string
  verifier_enabled: boolean
  dynamic_verify_enabled: boolean
  error: string | null
  worker_concurrency: number | null
  created_at: string
  updated_at: string
  vuln_confirmed: number
  vuln_false_positive: number
  vuln_pending: number
  files_total: number
  files_weighted: number
  files_skipped: number
  files_audited: number
  weight_exts?: WeightExt[]
  worker_rounds: number
  tokens_input: number
  tokens_output: number
  tokens_cached: number
  tokens_total: number
  phase_states?: Record<string, PhaseState>
  project_paused?: boolean
    recon_subphases?: ReconSubphase[]
    lab_setup_done?: boolean
    verifier_pending?: number
  }

export type ReconSubphase = {
  id: string
  label: string
  done: boolean
}

export type PhaseState = {
  paused: boolean
  running: boolean
  resumable: boolean
  force_new?: boolean
}

export type VulnTrackingStatus = 'none' | 'submitted' | 'ignored'

export type Vuln = {
  id: number
  project_id: number
  project_name?: string
  title: string
  vuln_type: string
  severity: string
  severity_score: number | null
  cwe: string | null
  file_path: string | null
  line_no: number | null
  status: string
  tracking_status?: VulnTrackingStatus
  evidence_level: string | null
  attack_surface: string | null
  required_account: string | null
  submission_tier: string | null
  submission_reason: string | null
  root_cause_key: string | null
  merged_into_id: number | null
  review_rounds: number
  return_reason: string | null
  intended_behavior: boolean
  report_path: string | null
  verifier_status?: string | null
  verifier_verified_url?: string | null
  created_at: string
  updated_at: string
}

export type VulnDetail = Vuln & {
  source_sink: string | null
  auth_premise: string | null
  http_request: string | null
  poc_code: string | null
  expected_evidence: string | null
  report_md: string | null
  merged_from_ids?: number[]
  verifier_poc?: string | null
  verifier_response?: string | null
  verifier_targets?: VerifierTarget[]
  verifier_fofa_query?: string | null
}

export type VerifierTarget = {
  host: string
  ip?: string
  port?: string
  title?: string
  protocol?: string
  status: 'success' | 'fail' | 'untested' | string
  note?: string
}

export type VulnFollowUpMessage = {
  id: string
  role: 'user' | 'assistant'
  content: string
  created_at: string
  reviewer_phase_run_id: number | null
}

export type VulnFollowUpThread = {
  vuln_id: number
  project_id: number
  reviewer_phase_run_id: number | null
  reviewer_context_available: boolean
  messages: VulnFollowUpMessage[]
}

export type LogEvent = {
  kind: string
  text?: string
  ts?: string
  source?: string
  command?: string
  output?: string
  exit_code?: number | null
  input?: number
  output_tokens?: number
  cached?: number
  total?: number
  phase?: string
  phase_label?: string
  tool?: string
  role?: string
  seq?: number
  traceback?: string
  duration_ms?: number
  phase_run_id?: number
  session?: number
  session_start?: boolean
}

export type EventsChunk = {
  events: LogEvent[]
  offset: number
  done: boolean
  oldest: number
  has_older: boolean
  total: number
  file_end: number
  session: number
  session_count: number
}

export type EventsQuery = {
  offset?: number
  limit?: number
  tail?: boolean
  before?: number
  phase?: string
  session?: number
}

export type PhaseReport = {
  id: string
  phase: string
  phase_label: string
  subphase: string
  subphase_label: string
  kind: string
  kind_label: string
  round: number | null
  title: string
  preview: string
  mtime: string
  size: number
}

export type PhaseReportGroup = {
  phase: string
  label: string
  count: number
  reports: PhaseReport[]
}

export type PhaseReportList = {
  phases: PhaseReportGroup[]
  count: number
}

export type PhaseReportDetail = PhaseReport & {
  content: string
}

export type Settings = {
  llm_providers: Array<{
    id: string
    name: string
    base_url: string
    wire_api: string
    env_key: string
    api_key_set: boolean
  }>
  llm_roles: Record<string, { provider_id: string; model: string; reasoning_effort: string }>
  llm_thread_limit: number
  github_pat_set: boolean
  fofa_key_set: boolean
  fofa_base_url: string
  default_model: string
  default_base_url: string
  default_api_key_set: boolean
  context_window: number
  http_proxy: string
  chat_proxy: string
}

export type LlmProbeBody = {
  base_url?: string | null
  api_key?: string | null
  model?: string | null
}

export type LlmModelList = {
  ok: boolean
  models: string[]
  count: number
  latency_ms: number | null
  error: string | null
}

export type LlmTest = {
  ok: boolean
  model: string
  latency_ms: number | null
  error: string | null
  reply: string | null
}

export type LiveLogPurge = {
  ok: boolean
  older_than_days: number
  projects: number
  files: number
  bytes: number
}

export type FofaProbeBody = {
  key?: string | null
  base_url?: string | null
}

export type FofaTest = {
  ok: boolean
  latency_ms: number | null
  username: string
  fcoin: number | null
  isvip: boolean | null
  error: string | null
  account_error: boolean
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  listProjects: () => request<Project[]>('/api/projects'),
  getProject: (id: number) => request<Project>(`/api/projects/${id}`),
  createGithub: (
    source_url: string,
    name = '',
    audit_mode: 'bounty' | 'full' = 'bounty',
    opts: {
      manual_lab?: boolean
      manual_lab_prompt?: string
      verifier_enabled?: boolean
      dynamic_verify_enabled?: boolean
    } = {},
  ) =>
    request<Project>('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source_type: 'github',
        source_url,
        name,
        audit_mode,
        manual_lab: Boolean(opts.manual_lab),
        manual_lab_prompt: opts.manual_lab_prompt || '',
        verifier_enabled: Boolean(opts.verifier_enabled),
        dynamic_verify_enabled: Boolean(opts.dynamic_verify_enabled),
      }),
    }),
  uploadZip: async (
    file: File,
    name = '',
    audit_mode: 'bounty' | 'full' = 'bounty',
    opts: {
      manual_lab?: boolean
      manual_lab_prompt?: string
      verifier_enabled?: boolean
      dynamic_verify_enabled?: boolean
    } = {},
  ) => {
    const fd = new FormData()
    fd.append('file', file)
    if (name) fd.append('name', name)
    fd.append('audit_mode', audit_mode)
    fd.append('manual_lab', opts.manual_lab ? 'true' : 'false')
    fd.append('manual_lab_prompt', opts.manual_lab_prompt || '')
    fd.append('verifier_enabled', opts.verifier_enabled ? 'true' : 'false')
    fd.append('dynamic_verify_enabled', opts.dynamic_verify_enabled ? 'true' : 'false')
    return request<Project>('/api/projects/upload', { method: 'POST', body: fd })
  },
  updateProject: (
    id: number,
    body: {
      audit_mode?: 'bounty' | 'full'
      manual_lab?: boolean
      manual_lab_prompt?: string | null
      verifier_enabled?: boolean
      dynamic_verify_enabled?: boolean
    },
  ) =>
    request<Project>(`/api/projects/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  pause: (id: number) => request(`/api/projects/${id}/pause`, { method: 'POST' }),
  resume: (id: number) => request(`/api/projects/${id}/resume`, { method: 'POST' }),
  pausePhase: (id: number, phase: string) =>
    request(`/api/projects/${id}/phases/${phase}/pause`, { method: 'POST' }),
  resumePhase: (id: number, phase: string) =>
    request(`/api/projects/${id}/phases/${phase}/resume`, { method: 'POST' }),
  restartPhase: (id: number, phase: string) =>
    request(`/api/projects/${id}/phases/${phase}/restart`, { method: 'POST' }),
  resetProgress: (id: number) =>
    request<Project>(`/api/projects/${id}/reset-progress`, { method: 'POST' }),
  cancel: (id: number) => request(`/api/projects/${id}/cancel`, { method: 'POST' }),
  deleteProject: (id: number) => request(`/api/projects/${id}`, { method: 'DELETE' }),
  events: (id: number, query: EventsQuery = {}) => {
    const q = new URLSearchParams()
    if (query.offset != null) q.set('offset', String(query.offset))
    if (query.limit != null) q.set('limit', String(query.limit))
    if (query.tail) q.set('tail', 'true')
    if (query.before != null) q.set('before', String(query.before))
    if (query.phase) q.set('phase', query.phase)
    if (query.session != null) q.set('session', String(query.session))
    const s = q.toString()
    return request<EventsChunk>(`/api/projects/${id}/events${s ? `?${s}` : ''}`)
  },
  listPhaseReports: (id: number) => request<PhaseReportList>(`/api/projects/${id}/reports`),
  getPhaseReport: (id: number, path: string) =>
    request<PhaseReportDetail>(`/api/projects/${id}/reports/file?path=${encodeURIComponent(path)}`),
  listVulns: (
    projectId?: number,
    status?: string,
    attackSurface?: string,
    submissionTier?: string,
    rootCauseKey?: string,
    trackingStatus?: string,
  ) => {
    const q = new URLSearchParams()
    if (projectId != null) q.set('project_id', String(projectId))
    if (status) q.set('status', status)
    if (attackSurface) q.set('attack_surface', attackSurface)
    if (submissionTier) q.set('submission_tier', submissionTier)
    if (rootCauseKey) q.set('root_cause_key', rootCauseKey)
    if (trackingStatus) q.set('tracking_status', trackingStatus)
    const s = q.toString()
    return request<Vuln[]>(`/api/vulns${s ? `?${s}` : ''}`)
  },
  getVuln: (id: number) => request<VulnDetail>(`/api/vulns/${id}`),
  updateVulnTracking: (id: number, tracking_status: VulnTrackingStatus) =>
    request<Vuln>(`/api/vulns/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tracking_status }),
    }),
  markVulns: (ids: number[], tracking_status: VulnTrackingStatus) =>
    request<Vuln[]>('/api/vulns/mark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, tracking_status }),
    }),
  listVulnFollowUps: (id: number) => request<VulnFollowUpThread>(`/api/vulns/${id}/follow-ups`),
  askVulnFollowUp: (id: number, question: string) =>
    request<VulnFollowUpThread>(`/api/vulns/${id}/follow-ups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question }),
    }),
  downloadVulns: async (ids: number[]) => {
    const res = await fetch('/api/vulns/download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    })
    if (!res.ok) throw new Error(await res.text())
    return res.blob()
  },
  getSettings: () => request<Settings>('/api/settings'),
  putSettings: (body: Record<string, unknown>) =>
    request<Settings>('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  listLlmModels: (body: LlmProbeBody) =>
    request<LlmModelList>('/api/settings/llm/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  testLlm: (body: LlmProbeBody) =>
    request<LlmTest>('/api/settings/llm/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  testFofa: (body: FofaProbeBody) =>
    request<FofaTest>('/api/settings/fofa/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  purgeLiveLogs: (olderThanDays: number) =>
    request<LiveLogPurge>('/api/settings/logs/purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ older_than_days: olderThanDays }),
    }),
}
