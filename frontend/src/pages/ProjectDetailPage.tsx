import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, formatApiError, withAccessTokenParam, type CustomAuditMode, type LogEvent, type Project, type Vuln } from '../api'
import { AuditModeSelect } from '../components/AuditModeSelect'
import { BountyScopeButton } from '../components/BountyScopeDialog'
import { DeleteProjectButton } from '../components/DeleteProjectButton'
import { ResetProgressButton } from '../components/ResetProgressButton'
import { ConversationComposer } from '../components/ConversationComposer'
import { CodeGraphExplorer } from '../components/CodeGraphExplorer'
import { GithubLink } from '../components/GithubLink'
import { LabControlPanel } from '../components/LabControlPanel'
import LiveLogPanel, { eventMatchesPhase } from '../components/LiveLogPanel'
import { ProjectSettingsButton } from '../components/ProjectSettingsDialog'
import PhaseFlow from '../components/PhaseFlow'
import { normalizeDynamicVerifyMode } from '../components/DynamicVerifyToggle'
import VulnDetailDialog from '../components/VulnDetailDialog'
import VulnGroupList from '../components/VulnGroupList'
import { WeightExtBadges } from '../components/WeightExtBadges'
import LlmThreadUsageBar from '../components/LlmThreadUsageBar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  formatAuditMode,
  formatAuditModeHint,
  formatMiningPaths,
  formatMiningProgress,
  formatProjectRunStatus,
  formatProjectStatus,
  formatTargetKind,
  formatTargetKindHint,
  formatTokens,
  projectRunBucket,
  projectStatusBadgeVariant,
  saveBlob,
  tokenBudgetReached,
} from '../lib/utils'
import { useI18n } from '@/i18n'
import {
  applyProjectRunToListCaches,
  projectDetailCacheKey,
  readProjectSnapshot,
  rememberProjectRun,
  writeJsonCache,
} from '../lib/listCache'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const PhaseReportsPanel = lazy(() => import('../components/PhaseReportsPanel'))

const LOG_PAGE = 100
const PHASE_TABS = [
  ['recon', 'detail.phase.recon'],
  ['code-intel', 'detail.phase.codeIntel'],
  ['worker', 'detail.phase.worker'],
  ['reviewer', 'detail.phase.reviewer'],
  ['verifier', 'detail.phase.verifier'],
  ['attack_chain', 'detail.phase.attackChain'],
  ['vuln_dedup', 'detail.phase.vulnDedup'],
] as const
const REVIEWER_LOG_TABS = [
  ['reviewer-lab', 'detail.sub.lab'],
  ['reviewer-review', 'detail.sub.review'],
] as const
const RECON_LOG_TABS = [
  ['recon-map', 'detail.sub.map', 'map'],
  ['recon-source-ext', 'detail.sub.ext', 'source_ext'],
  ['recon-old-vuln', 'detail.sub.oldVuln', 'old_vulns'],
  ['recon-mark', 'detail.sub.mark', 'mark'],
] as const

function workerLogTabs(
  project: {
    heuristic_enabled?: boolean
    fast_enabled?: boolean
    bypass_enabled?: boolean
    unconstrained_enabled?: boolean
  },
  t: (key: string) => string,
) {
  const tabs: [string, string][] = []
  if (project.heuristic_enabled !== false) tabs.push(['mine', t('mining.heuristicShort')])
  if (project.fast_enabled === true) tabs.push(['fast', t('mining.fast')])
  if (project.bypass_enabled === true) tabs.push(['bypass', t('mining.bypass')])
  if (project.unconstrained_enabled === true) tabs.push(['unconstrained', t('mining.unconstrained')])
  tabs.push(['fix', t('detail.sub.fix')])
  return tabs
}

function isSessionStart(ev: LogEvent): boolean {
  if (ev.session_start) return true
  return ev.kind === 'system' && (ev.text || '').includes('新开对话')
}

function controlPhaseOf(logPhase: string): 'recon' | 'code-intel' | 'worker' | 'reviewer' | 'verifier' | 'attack_chain' | 'vuln_dedup' {
  if (logPhase === 'verifier') return 'verifier'
  if (logPhase === 'attack_chain' || logPhase === 'attack-chain') return 'attack_chain'
  if (logPhase === 'vuln_dedup' || logPhase === 'vuln-dedup') return 'vuln_dedup'
  if (logPhase === 'code-intel' || logPhase === 'code_intel') return 'code-intel'
  if (logPhase === 'reviewer' || logPhase === 'reviewer-lab' || logPhase === 'reviewer_lab' || logPhase === 'reviewer-review') return 'reviewer'
  if (
    logPhase === 'recon' ||
    logPhase === 'recon-map' ||
    logPhase === 'recon-source-ext' ||
    logPhase === 'recon_source_ext' ||
    logPhase === 'recon-old-vuln' ||
    logPhase === 'recon-old-vuln-ghsa' ||
    logPhase === 'recon-mark' ||
    logPhase === 'recon_mark' ||
    logPhase === 'recon_old_vuln' ||
    logPhase === 'recon_old_vuln_ghsa'
  ) {
    return 'recon'
  }
  return 'worker'
}

function defaultPhaseTab(phase: string, status: string): string {
  if (phase === 'vuln_dedup' || phase === 'vuln-dedup') return 'vuln_dedup'
  if (phase === 'attack_chain' || phase === 'attack-chain') return 'attack_chain'
  if (phase === 'code_intel' || phase === 'code-intel') return 'code-intel'
  if (phase === 'verifier') return 'verifier'
  if (status === 'completed' || phase === 'done' || phase === 'reviewer' || status === 'reviewing') {
    return 'reviewer'
  }
  if (phase === 'unconstrained-worker' || phase === 'unconstrained') return 'unconstrained'
  if (phase === 'fast-worker' || phase === 'fast') return 'fast'
  if (phase === 'bypass-worker' || phase === 'bypass') return 'bypass'
  if (phase === 'worker' || phase === 'fix' || status === 'auditing') return 'worker'
  return 'recon'
}

function cachedProject(id: number) {
  if (!Number.isFinite(id) || id <= 0) return null
  return readProjectSnapshot<Project>(id)
}

export default function ProjectDetailPage() {
  const { t } = useI18n()
  const { id } = useParams()
  const navigate = useNavigate()
  const projectId = Number(id)
  const initial = cachedProject(projectId)
  const [project, setProject] = useState<Project | null>(initial?.project ?? null)
  const [detailReady, setDetailReady] = useState(() => Boolean(initial && !initial.partial))
  const [metaReady, setMetaReady] = useState(() => Boolean(initial))
  const [customModes, setCustomModes] = useState<CustomAuditMode[]>([])
  const [events, setEvents] = useState<LogEvent[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [vulnsLoading, setVulnsLoading] = useState(false)
  const [selectedVulnIds, setSelectedVulnIds] = useState<number[]>([])
  const [detailVulnId, setDetailVulnId] = useState<number | null>(null)
  const [tab, setTab] = useState<'logs' | 'reports' | 'vulns'>('logs')
  const [phaseFilter, setPhaseFilter] = useState(() =>
    initial?.project ? defaultPhaseTab(initial.project.phase, initial.project.status) : 'recon',
  )
  const [hasOlder, setHasOlder] = useState(false)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [revealLimit, setRevealLimit] = useState(LOG_PAGE)
  const [streamFrom, setStreamFrom] = useState<number | null>(null)
  const [logSession, setLogSession] = useState<number | null>(null)
  const [displaySession, setDisplaySession] = useState(1)
  const [sessionCount, setSessionCount] = useState(1)
  const [phaseRunning, setPhaseRunning] = useState<boolean | null>(null)
  const [actionError, setActionError] = useState('')
  const [graphOpen, setGraphOpen] = useState(false)
  const [runBusy, setRunBusy] = useState(false)
  const [ciBusy, setCiBusy] = useState(false)
  const [dedupBusy, setDedupBusy] = useState(false)
  const [loadError, setLoadError] = useState('')
  const oldestRef = useRef(0)
  const fileEndRef = useRef(0)
  const phaseRef = useRef(phaseFilter)
  const syncedPhase = useRef(Boolean(initial))
  const etagRef = useRef(initial && !initial.partial ? initial.project.etag || '' : '')
  const loadingOlderRef = useRef(false)
  const atTopRef = useRef(false)
  const followLiveRef = useRef(true)
  const displaySessionRef = useRef(1)
  const sessionCountRef = useRef(1)

  const applyProject = (next: Project) => {
    setProject(next)
    setDetailReady(true)
    if (next.etag) etagRef.current = next.etag
    writeJsonCache(projectDetailCacheKey(projectId), next)
    rememberProjectRun(next)
  }

  const applyRunChange = (next: Project) => {
    applyProjectRunToListCaches(next)
    applyProject(next)
  }

  const selectPhase = (p: string) => {
    if (p === phaseFilter) return
    setPhaseFilter(p)
    followLiveRef.current = true
    displaySessionRef.current = 1
    sessionCountRef.current = 1
    setDisplaySession(1)
    setSessionCount(1)
    setLogSession(null)
    setPhaseRunning(null)
  }

  useEffect(() => {
    phaseRef.current = phaseFilter
  }, [phaseFilter])

  useEffect(() => {
    const snap = cachedProject(projectId)
    setProject(snap?.project ?? null)
    setDetailReady(Boolean(snap && !snap.partial))
    setMetaReady(Boolean(snap))
    syncedPhase.current = Boolean(snap)
    etagRef.current = snap && !snap.partial ? snap.project.etag || '' : ''
    setPhaseFilter(snap?.project ? defaultPhaseTab(snap.project.phase, snap.project.status) : 'recon')
    fileEndRef.current = 0
    oldestRef.current = 0
    followLiveRef.current = true
    displaySessionRef.current = 1
    sessionCountRef.current = 1
    setStreamFrom(null)
    setEvents([])
    setVulns([])
    setSelectedVulnIds([])
    setDetailVulnId(null)
    setHasOlder(false)
    setRevealLimit(LOG_PAGE)
    setLogSession(null)
    setDisplaySession(1)
    setSessionCount(1)
    setPhaseRunning(null)
    setLoadError('')
  }, [projectId])

  useEffect(() => {
    api.listCustomAuditModes().then(setCustomModes).catch(() => setCustomModes([]))
  }, [])

  useEffect(() => {
    if (!projectId) return
    let alive = true
    const refreshMeta = async () => {
      try {
        const p = await api.getProject(projectId, etagRef.current || undefined)
        if (!alive) return
        if (p.notModified || p.unchanged) return
        etagRef.current = p.etag || ''
        setProject(p)
        setDetailReady(true)
        setMetaReady(true)
        writeJsonCache(projectDetailCacheKey(projectId), p)
        rememberProjectRun(p)
        if (!syncedPhase.current) {
          syncedPhase.current = true
          selectPhase(defaultPhaseTab(p.phase, p.status))
        }
        setLoadError('')
      } catch (err) {
        if (!alive) return
        if (!etagRef.current) {
          const timedOut =
            err instanceof DOMException && (err.name === 'TimeoutError' || err.name === 'AbortError')
          setLoadError(timedOut ? t('detail.loadTimeout') : t('detail.loadFail'))
        }
      }
    }
    const stop = startVisibilityPoll(refreshMeta, 5000)
    return () => {
      alive = false
      stop()
    }
  }, [projectId])

  useEffect(() => {
    if (!projectId || tab !== 'vulns') return
    let alive = true
    const refreshVulns = async () => {
      setVulnsLoading(true)
      try {
        const vs = await api.listAllVulns({ projectId })
        if (alive) setVulns(vs)
      } catch {
        /* ignore transient */
      } finally {
        if (alive) setVulnsLoading(false)
      }
    }
    const stop = startVisibilityPoll(refreshVulns, 5000)
    return () => {
      alive = false
      stop()
    }
  }, [projectId, tab])

  useEffect(() => {
    if (!projectId || !metaReady) return
    let alive = true
    oldestRef.current = 0
    setHasOlder(false)
    setRevealLimit(LOG_PAGE)
    setEvents([])
    api
      .events(projectId, {
        tail: true,
        limit: LOG_PAGE,
        phase: phaseFilter,
        session: logSession ?? undefined,
      })
      .then((d) => {
        if (!alive) return
        setEvents(d.events)
        oldestRef.current = d.oldest
        setHasOlder(d.has_older)
        fileEndRef.current = d.file_end
        setStreamFrom(d.file_end)
        const count = d.session_count || 1
        const sess = d.session || 1
        sessionCountRef.current = count
        displaySessionRef.current = sess
        setSessionCount(count)
        setDisplaySession(sess)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [projectId, phaseFilter, logSession, metaReady])

  useEffect(() => {
    if (!projectId || streamFrom == null) return
    let mounted = true
    let source: EventSource | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let backoffMs = 800

    const connect = () => {
      source?.close()
      const from = Math.max(fileEndRef.current, streamFrom)
      const params = new URLSearchParams({ from_offset: String(from) })
      if (phaseRef.current) params.set('phase', phaseRef.current)
      if (logSession != null) params.set('session', String(logSession))
      source = new EventSource(`/api/projects/${projectId}/stream?${withAccessTokenParam(params).toString()}`)
      source.onmessage = (event) => {
        if (!mounted) return
        backoffMs = 800
        let data: Record<string, unknown>
        try {
          data = JSON.parse(event.data)
        } catch {
          return
        }
        if (data.type === 'status') {
          const nextStatus = typeof data.status === 'string' ? data.status : undefined
          const nextPhase = typeof data.phase === 'string' ? data.phase : undefined
          if (nextStatus || nextPhase) {
            setProject((cur) => {
              if (!cur) return cur
              const next = {
                ...cur,
                status: nextStatus ?? cur.status,
                phase: nextPhase ?? cur.phase,
              }
              rememberProjectRun(next)
              return next
            })
          }
          return
        }
        if (data.type === 'event' || data.kind) {
          const { type: _t, ...ev } = data
          if (!ev.kind) return
          const seq = typeof ev.seq === 'number' ? ev.seq : undefined
          if (seq != null) fileEndRef.current = Math.max(fileEndRef.current, seq + 1)
          const evSession = typeof ev.session === 'number' ? ev.session : undefined
          if (eventMatchesPhase(ev as LogEvent, phaseRef.current)) {
            const started =
              (evSession != null && evSession > sessionCountRef.current) ||
              (isSessionStart(ev as LogEvent) && evSession == null)
            if (started) {
              const next = evSession ?? sessionCountRef.current + 1
              sessionCountRef.current = Math.max(sessionCountRef.current, next)
              setSessionCount(sessionCountRef.current)
              if (followLiveRef.current) {
                displaySessionRef.current = next
                setDisplaySession(next)
                oldestRef.current = seq ?? 0
                setHasOlder(false)
                setRevealLimit(LOG_PAGE)
                setEvents([ev as LogEvent])
                return
              }
            }
          }
          if (!eventMatchesPhase(ev as LogEvent, phaseRef.current)) return
          if (evSession != null && evSession !== displaySessionRef.current) return
          // 已追平后的历史重放（seq 早于当前窗口）直接丢掉，避免早期日志灌进「最近 100」。
          if (seq != null && oldestRef.current > 0 && seq < oldestRef.current) return
          setEvents((prev) => {
            if (seq != null && prev.some((x) => x.seq === seq)) return prev
            return [...prev, ev as LogEvent]
          })
        }
      }
      source.onerror = () => {
        source?.close()
        if (mounted) scheduleReconnect()
      }
    }

    const scheduleReconnect = () => {
      if (!mounted || reconnectTimer) return
      const wait = backoffMs
      backoffMs = Math.min(Math.round(backoffMs * 1.8), 8000)
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null
        if (mounted) connect()
      }, wait)
    }

    const start = window.setTimeout(connect, 0)
    return () => {
      mounted = false
      window.clearTimeout(start)
      if (reconnectTimer) clearTimeout(reconnectTimer)
      source?.close()
    }
  }, [projectId, streamFrom, phaseFilter, logSession])

  const loadOlder = () => {
    if (!projectId || loadingOlderRef.current || !hasOlder) return
    loadingOlderRef.current = true
    setLoadingOlder(true)
    const before = oldestRef.current
    api
      .events(projectId, {
        before,
        limit: LOG_PAGE,
        phase: phaseFilter,
        session: logSession ?? displaySession,
      })
      .then((d) => {
        if (!atTopRef.current) return
        setEvents((prev) => {
          const seen = new Set(prev.map((e) => e.seq).filter((x): x is number => x != null))
          const older = d.events.filter((e) => e.seq == null || !seen.has(e.seq))
          return [...older, ...prev]
        })
        const added = d.events.length
        if (added) setRevealLimit((n) => n + added)
        oldestRef.current = d.oldest
        setHasOlder(d.has_older)
      })
      .catch(() => undefined)
      .finally(() => {
        loadingOlderRef.current = false
        setLoadingOlder(false)
      })
  }

  if (!project) {
    return (
      <div className="text-slate-400">
        {loadError ? <p className="text-sm text-red-300">{loadError}</p> : t('common.loading')}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link to="/" className="text-sm text-slate-400 hover:underline">
            {t('detail.back')}
          </Link>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold">{project.name}</h1>
            <GithubLink project={project} variant="button" />
          </div>
          <div className="mt-2">
            <PhaseFlow
              phase={project.phase}
              status={project.status}
              reconDone={project.recon_done}
              codeIntelEnabled={project.code_intel_enabled === true}
              codeIntelStatus={project.code_intel_status}
              codeIntelDone={project.code_intel_done}
              filesAudited={project.files_audited}
              filesSkipped={project.files_skipped}
              filesTotal={project.files_total}
              filesWeight100={project.files_weight100}
              filesWeight100Audited={project.files_weight100_audited}
              workerRounds={project.worker_rounds}
              vulnPending={project.vuln_pending}
              reconSubphases={project.recon_subphases}
              labSetupDone={project.lab_setup_done}
              manualLab={Boolean(project.manual_lab)}
              dynamicVerifyEnabled={project.dynamic_verify_enabled}
              dynamicVerifyMode={normalizeDynamicVerifyMode(project.dynamic_verify_mode, project.dynamic_verify_enabled)}
              verifierEnabled={project.verifier_enabled}
              verifierPending={project.verifier_pending}
              attackChainEnabled={project.attack_chain_enabled}
              attackChainDone={project.attack_chain_done}
              attackChainStopped={project.attack_chain_stopped}
              heuristicEnabled={project.heuristic_enabled}
              heuristicLite={project.heuristic_lite}
              fastEnabled={project.fast_enabled}
              fastQueueFrozen={project.fast_queue_frozen}
              sinksQueued={project.sinks_queued}
              sinksDone={project.sinks_done}
              bypassEnabled={project.bypass_enabled}
              bypassQueueFrozen={project.bypass_queue_frozen}
              bypassQueued={project.bypass_queued}
              bypassDone={project.bypass_done}
              unconstrainedEnabled={project.unconstrained_enabled}
              unconstrainedDone={project.unconstrained_done}
              heuristicStopped={project.heuristic_stopped}
              fastStopped={project.fast_stopped}
              bypassStopped={project.bypass_stopped}
              onSelect={(pid) => {
                setTab('logs')
                if (pid !== 'done') selectPhase(pid)
              }}
            />
          </div>
        </div>
          <div className="flex flex-col items-end gap-2">
          <LlmThreadUsageBar />
          <div className="flex flex-wrap justify-end gap-2">
            <ProjectSettingsButton
              project={project}
              disabled={!detailReady}
              onSaved={(next) => {
                applyProject(next)
                setActionError('')
              }}
            />
            <Button
              variant="outline"
              disabled={runBusy || project.status === 'completed'}
              title={project.status === 'completed' ? t('detail.pauseCompleted') : undefined}
              onClick={() => {
                setActionError('')
                const prev = project
                const next = { ...project, status: 'paused', project_paused: true }
                applyRunChange(next)
                setRunBusy(true)
                void api
                  .pause(projectId)
                  .then(() => api.getProject(projectId))
                  .then((fresh) => {
                    if (!fresh.notModified && !fresh.unchanged) applyRunChange(fresh)
                  })
                  .catch((e) => {
                    applyRunChange(prev)
                    setActionError(formatApiError(e))
                  })
                  .finally(() => setRunBusy(false))
              }}
            >
              {t('detail.pauseAll')}
            </Button>
            <Button
              variant="outline"
              disabled={runBusy || tokenBudgetReached(project)}
              title={
                tokenBudgetReached(project)
                  ? t('detail.tokenCap')
                  : undefined
              }
              onClick={() => {
                setActionError('')
                const prev = project
                const running = project.recon_done
                const next = {
                  ...project,
                  status: running ? 'auditing' : 'recon',
                  phase: running ? (project.phase === 'pending' || project.phase === 'recon' ? 'worker' : project.phase) : 'recon',
                  project_paused: false,
                }
                applyRunChange(next)
                setRunBusy(true)
                void api
                  .resume(projectId)
                  .then(() => api.getProject(projectId))
                  .then((fresh) => {
                    if (!fresh.notModified && !fresh.unchanged) applyRunChange(fresh)
                  })
                  .catch((e) => {
                    applyRunChange(prev)
                    setActionError(formatApiError(e))
                  })
                  .finally(() => setRunBusy(false))
              }}
            >
              {t('detail.resumeAll')}
            </Button>
            <ResetProgressButton project={project} onReset={applyProject} />
            <Button variant="destructive" onClick={() => api.cancel(projectId)}>
              {t('detail.stop')}
            </Button>
            <DeleteProjectButton
              projectId={projectId}
              projectName={project.name}
              onDeleted={() => navigate('/', { replace: true })}
            />
          </div>
        </div>
      </div>
      {actionError ? <p className="text-sm text-red-300">{actionError}</p> : null}
      {project.source_sync_error ? (
        <Card className="border-amber-500/40 bg-amber-950/30">
          <CardContent className="space-y-2 pt-4 text-sm text-amber-100">
            <p className="font-medium text-amber-50">{t('detail.syncFailTitle')}</p>
            <p className="break-words text-amber-100/90">{project.source_sync_error}</p>
          </CardContent>
        </Card>
      ) : null}
      {project.source_sync_notice ? (
        <Card className="border-sky-500/40 bg-sky-950/30">
          <CardContent className="space-y-2 pt-4 text-sm text-sky-100">
            <p className="font-medium text-sky-50">{t('detail.syncOkTitle')}</p>
            <p className="break-words text-sky-100/90">{project.source_sync_notice}</p>
          </CardContent>
        </Card>
      ) : null}
      <CodeGraphExplorer projectId={projectId} open={graphOpen} onOpenChange={setGraphOpen} />

      {normalizeDynamicVerifyMode(project.dynamic_verify_mode, project.dynamic_verify_enabled) ===
        'lab' && <LabControlPanel project={project} />}

      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
          <Badge variant={projectStatusBadgeVariant(project.status, project.project_paused)}>
            {projectRunBucket(project.status, project.project_paused) === 'running'
              ? formatProjectStatus(project.status)
              : formatProjectRunStatus(project.status, project.project_paused)}
          </Badge>
          {project.status === 'paused' || project.project_paused || project.status === 'completed' ? (
            <AuditModeSelect
              value={project.audit_mode}
              customModeId={project.custom_audit_mode_id}
              customModes={customModes}
              customModeName={project.custom_audit_mode_name}
              showHint={false}
              onValueChange={async (value) => {
                try {
                  const body: {
                    audit_mode: 'bounty' | 'full' | 'custom'
                    custom_audit_mode_id?: number | null
                  } = { audit_mode: value }
                  if (value === 'custom') {
                    const id = project.custom_audit_mode_id ?? customModes[0]?.id ?? null
                    if (id == null) return
                    body.custom_audit_mode_id = id
                  }
                  const next = await api.updateProject(projectId, body)
                  applyProject(next)
                } catch {
                  /* ignore */
                }
              }}
              onCustomModeIdChange={async (id) => {
                if (id == null) return
                try {
                  const next = await api.updateProject(projectId, {
                    audit_mode: 'custom',
                    custom_audit_mode_id: id,
                  })
                  applyProject(next)
                } catch {
                  /* ignore */
                }
              }}
            />
          ) : (
            <span className="inline-flex items-center gap-2">
              <Badge
                variant="outline"
                title={formatAuditModeHint(project.audit_mode, project.custom_audit_mode_name)}
              >
                {formatAuditMode(project.audit_mode, project.custom_audit_mode_name)}
              </Badge>
              {project.audit_mode === 'custom' ? null : <BountyScopeButton />}
            </span>
          )}
          <Badge variant="outline" title={formatTargetKindHint(project.target_kind)}>
            {formatTargetKind(project.target_kind)}
          </Badge>
          <Badge variant="outline">{formatMiningPaths(project)}</Badge>
          <Badge variant="outline" title={project.llm_model ? t('detail.modelProject') : t('detail.modelGlobal')}>
            {project.llm_model || t('common.globalModel')}
          </Badge>
          <span>
            tokens {formatTokens(project.tokens_input + project.tokens_output)}
            {project.max_token_usage > 0
              ? t('detail.tokenCapSuffix', { cap: formatTokens(project.max_token_usage) })
              : ''}
          </span>
          <span>{formatMiningProgress(project)}</span>
          <span>
            {t('detail.vulnCounts', {
              confirmed: project.vuln_confirmed,
              pending: project.vuln_pending,
              fp: project.vuln_false_positive,
            })}
          </span>
        </div>
        <WeightExtBadges exts={project.weight_exts} />
        <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">
          {formatTargetKindHint(project.target_kind)}{' '}
          {formatAuditModeHint(project.audit_mode, project.custom_audit_mode_name)}
          {project.fast_enabled ? t('detail.hint.fast') : ''}
          {project.bypass_enabled ? t('detail.hint.bypass') : ''}
          {project.unconstrained_enabled ? t('detail.hint.unconstrained') : ''}
          {project.code_intel_enabled === true ? t('detail.hint.ciOn') : t('detail.hint.ciOff')}
          {project.status === 'paused' || project.project_paused || project.status === 'completed'
            ? t('detail.hint.modeEditable')
            : ''}
        </p>
      </div>

      <div className="flex gap-2">
        <Button variant={tab === 'logs' ? 'default' : 'outline'} onClick={() => setTab('logs')}>
          {t('detail.tab.logs')}
        </Button>
        <Button variant={tab === 'reports' ? 'default' : 'outline'} onClick={() => setTab('reports')}>
          {t('detail.tab.reports')}
        </Button>
        <Button variant={tab === 'vulns' ? 'default' : 'outline'} onClick={() => setTab('vulns')}>
          {t('detail.tab.vulns')}
        </Button>
      </div>

      {tab === 'reports' ? (
        <Suspense fallback={<div className="text-sm text-muted-foreground">{t('detail.reportsLoading')}</div>}>
          <PhaseReportsPanel projectId={projectId} initialPhase={controlPhaseOf(phaseFilter)} />
        </Suspense>
      ) : null}

      {tab === 'logs' ? (
        <Card>
          <CardContent className="p-3">
          <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
            <div className="vh-phase-tabs">
              {PHASE_TABS.map(([k, labelKey]) => (
                <div key={k} className="vh-phase-branch">
                  <Button
                    variant={controlPhaseOf(phaseFilter) === k ? 'default' : 'outline'}
                    onClick={() => selectPhase(k)}
                  >
                    {t(labelKey)}
                  </Button>
                  {k === 'recon' ? (
                    <div className="vh-phase-subs">
                      {RECON_LOG_TABS.map(([sk, slabelKey, subId]) => {
                        const done = Boolean(project.recon_subphases?.find((s) => s.id === subId)?.done)
                        return (
                          <Button
                            key={sk}
                            className="h-6 px-2 text-[11px]"
                            variant={phaseFilter === sk ? 'default' : 'outline'}
                            onClick={() => selectPhase(sk)}
                          >
                            {t(slabelKey)}
                            {done ? ' ✓' : ' ○'}
                          </Button>
                        )
                      })}
                    </div>
                  ) : null}
                  {k === 'worker' ? (
                    <div className="vh-phase-subs">
                      {workerLogTabs(project, t).map(([sk, slabel]) => (
                        <Button
                          key={sk}
                          className="h-6 px-2 text-[11px]"
                          variant={phaseFilter === sk ? 'default' : 'outline'}
                          onClick={() => selectPhase(sk)}
                        >
                          {slabel}
                        </Button>
                      ))}
                    </div>
                  ) : null}
                  {k === 'reviewer' ? (
                    <div className="vh-phase-subs">
                      {(normalizeDynamicVerifyMode(project.dynamic_verify_mode, project.dynamic_verify_enabled) === 'lab'
                        ? REVIEWER_LOG_TABS
                        : REVIEWER_LOG_TABS.filter(([sk]) => sk !== 'reviewer-lab')
                      ).map(([sk, slabelKey]) => (
                        <Button
                          key={sk}
                          className="h-6 px-2 text-[11px]"
                          variant={phaseFilter === sk ? 'default' : 'outline'}
                          onClick={() => selectPhase(sk)}
                        >
                          {t(slabelKey)}
                          {sk === 'reviewer-lab' ? (project.lab_setup_done ? ' ✓' : ' ○') : ''}
                        </Button>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
          <LiveLogPanel
            events={events}
            autoScroll
            phaseFilter={phaseFilter}
            hasOlder={hasOlder}
            loadingOlder={loadingOlder}
            revealLimit={revealLimit}
            onLoadOlder={loadOlder}
            atTopRef={atTopRef}
            session={displaySession}
            sessionCount={sessionCount}
            phaseRunning={phaseRunning}
            onSessionChange={(n) => {
              followLiveRef.current = n == null || n >= sessionCountRef.current
              const next = n ?? sessionCountRef.current
              displaySessionRef.current = next
              setDisplaySession(next)
              setLogSession(n)
            }}
          />
          {phaseFilter === 'code-intel' || phaseFilter === 'code_intel' ? (
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {project.code_intel_enabled !== true ? (
                <span className="text-xs text-muted-foreground">
                  {t('detail.ciOff')}
                </span>
              ) : null}
              <Button
                size="sm"
                variant="outline"
                disabled={
                  ciBusy ||
                  project.code_intel_enabled !== true ||
                  project.status === 'cancelled' ||
                  project.status === 'error'
                }
                onClick={() => {
                  setActionError('')
                  setCiBusy(true)
                  void api
                    .rebuildCodeIntel(projectId)
                    .then(() => api.getProject(projectId))
                    .then((fresh) => {
                      if (!fresh.notModified && !fresh.unchanged) applyRunChange(fresh)
                    })
                    .catch((e) => setActionError(formatApiError(e)))
                    .finally(() => setCiBusy(false))
                }}
              >
                {ciBusy ? t('detail.ciBusy') : t('detail.ciRebuild')}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={
                  ciBusy ||
                  project.code_intel_enabled !== true ||
                  (project.code_intel_status !== 'ready' && project.code_intel_status !== 'stale')
                }
                title={t('detail.ciGraphTip')}
                onClick={() => {
                  setActionError('')
                  setCiBusy(true)
                  void api
                    .openCodeIntelUi(projectId)
                    .then((out) => {
                      if (out.builtin || !out.url) {
                        setGraphOpen(true)
                        return
                      }
                      window.open(out.url, '_blank', 'noopener,noreferrer')
                    })
                    .catch((e) => setActionError(formatApiError(e)))
                    .finally(() => setCiBusy(false))
                }}
              >
                {t('detail.ciGraph')}
              </Button>
              {project.code_intel_status === 'stale' ? (
                <span className="text-xs text-amber-300">{t('detail.ciStale')}</span>
              ) : null}
              {project.code_intel_status === 'degraded' && project.code_intel_error ? (
                <span className="text-xs text-red-300">{project.code_intel_error}</span>
              ) : null}
            </div>
          ) : (
            <ConversationComposer
              projectId={projectId}
              logPhase={phaseFilter}
              session={displaySession}
              sessionCount={sessionCount}
              projectStatus={project.status}
              onRunningChange={setPhaseRunning}
              onSent={() => {
                followLiveRef.current = true
                displaySessionRef.current = sessionCountRef.current
                setDisplaySession(sessionCountRef.current)
                setLogSession(null)
                void api
                  .getProject(projectId)
                  .then((fresh) => {
                    if (!fresh.notModified && !fresh.unchanged) applyRunChange(fresh)
                  })
                  .catch(() => undefined)
              }}
            />
          )}
          </CardContent>
        </Card>
      ) : tab === 'vulns' ? (
        <>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button
              variant="outline"
              title={t('detail.dedupTip')}
              disabled={dedupBusy || (!selectedVulnIds.length && vulns.length === 0)}
              onClick={() => {
                const ids = selectedVulnIds.length ? selectedVulnIds : vulns.map((v) => v.id)
                if (!ids.length) return
                setActionError('')
                setDedupBusy(true)
                void api
                  .requestVulnDedup(projectId, ids)
                  .then(() => {
                    setTab('logs')
                    selectPhase('vuln_dedup')
                  })
                  .catch((e) => setActionError(formatApiError(e)))
                  .finally(() => setDedupBusy(false))
              }}
            >
              {dedupBusy ? t('detail.dedupBusy') : t('detail.dedup')}
            </Button>
            <Button
              onClick={() => {
                const ids = selectedVulnIds.length ? selectedVulnIds : vulns.map((v) => v.id)
                if (!ids.length) return
                void api
                  .downloadVulns(ids)
                  .then((blob) => saveBlob(blob, 'vulns.zip'))
                  .catch(() => undefined)
              }}
              disabled={!selectedVulnIds.length && vulns.length === 0}
            >
              {t('vulns.batchDownload')}
            </Button>
          </div>
          <Card className="gap-0 divide-y divide-border py-0">
            <VulnGroupList
              vulns={vulns}
              activeId={detailVulnId}
              selectedIds={selectedVulnIds}
              emptyText={vulnsLoading ? t('detail.vulnsLoading') : t('detail.noVulns')}
              onToggleSelect={(vid, checked) =>
                setSelectedVulnIds((prev) => (checked ? [...prev, vid] : prev.filter((x) => x !== vid)))
              }
              onSelectVuln={setDetailVulnId}
              projectKindById={new Map([[project.id, project.target_kind]])}
            />
          </Card>
          <VulnDetailDialog
            vulnId={detailVulnId}
            onClose={() => setDetailVulnId(null)}
            onSelectVuln={setDetailVulnId}
            projectName={project.name}
            dynamicVerifyMode={project.dynamic_verify_mode}
            dynamicVerifyEnabled={project.dynamic_verify_enabled}
            showProjectLink={false}
            onUpdated={(detail) => {
              setVulns((prev) =>
                prev.map((v) =>
                  v.id === detail.id
                    ? {
                        ...v,
                        tracking_status: detail.tracking_status,
                        evidence_level: detail.evidence_level,
                        verifier_status: detail.verifier_status,
                        verifier_verified_url: detail.verifier_verified_url,
                      }
                    : v,
                ),
              )
            }}
          />
        </>
      ) : null}
    </div>
  )
}
