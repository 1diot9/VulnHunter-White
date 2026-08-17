import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type LogEvent, type Project, type Vuln } from '../api'
import { AuditModeSelect } from '../components/AuditModeSelect'
import LiveLogPanel, { eventMatchesPhase } from '../components/LiveLogPanel'
import { ManualLabPromptEditor } from '../components/ManualLabFields'
import { VerifierToggle } from '../components/VerifierToggle'
import PhaseFlow from '../components/PhaseFlow'
import VulnGroupList from '../components/VulnGroupList'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  formatAuditMode,
  formatAuditModeHint,
  formatFileProgress,
  formatTokens,
} from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const PhaseReportsPanel = lazy(() => import('../components/PhaseReportsPanel'))

const LOG_PAGE = 100
const PHASE_TABS = [
  ['recon', '侦察'],
  ['worker', '挖掘'],
  ['reviewer', '审核'],
  ['verifier', '验证'],
] as const
const WORKER_LOG_TABS = [
  ['mine', '挖掘'],
  ['fix', '修复'],
] as const
const REVIEWER_LOG_TABS = [
  ['reviewer-lab', '环境搭建'],
  ['reviewer-review', '审核'],
] as const
const RECON_LOG_TABS = [
  ['recon-map', '地图/鉴权', 'map'],
  ['recon-source-ext', '扩展名', 'source_ext'],
  ['recon-old-vuln', '历史漏洞', 'old_vulns'],
  ['recon-mark', '盖章', 'mark'],
] as const

function isSessionStart(ev: LogEvent): boolean {
  if (ev.session_start) return true
  return ev.kind === 'system' && (ev.text || '').includes('新开对话')
}

function controlPhaseOf(logPhase: string): 'recon' | 'worker' | 'reviewer' | 'verifier' {
  if (logPhase === 'verifier') return 'verifier'
  if (logPhase === 'reviewer' || logPhase === 'reviewer-lab' || logPhase === 'reviewer_lab' || logPhase === 'reviewer-review') return 'reviewer'
  if (
    logPhase === 'recon' ||
    logPhase === 'recon-map' ||
    logPhase === 'recon-source-ext' ||
    logPhase === 'recon_source_ext' ||
    logPhase === 'recon-old-vuln' ||
    logPhase === 'recon-mark' ||
    logPhase === 'recon_mark' ||
    logPhase === 'recon_old_vuln'
  ) {
    return 'recon'
  }
  return 'worker'
}

function defaultPhaseTab(phase: string, status: string): string {
  if (phase === 'verifier') return 'verifier'
  if (status === 'completed' || phase === 'done' || phase === 'reviewer' || status === 'reviewing') {
    return 'reviewer'
  }
  if (phase === 'worker' || phase === 'fix' || status === 'auditing') return 'worker'
  return 'recon'
}

function PhaseRunControls({
  projectId,
  phase,
  project,
}: {
  projectId: number
  phase: 'recon' | 'worker' | 'reviewer' | 'verifier'
  project: Project
}) {
  const [busy, setBusy] = useState<string | null>(null)
  const state = project.phase_states?.[phase]
  const paused = Boolean(state?.paused || project.project_paused)
  const label = phase === 'recon' ? '侦察' : phase === 'reviewer' ? '审核' : phase === 'verifier' ? '验证' : '挖掘'
  const run = async (kind: 'pause' | 'resume' | 'restart') => {
    setBusy(kind)
    try {
      if (kind === 'pause') await api.pausePhase(projectId, phase)
      else if (kind === 'resume') await api.resumePhase(projectId, phase)
      else await api.restartPhase(projectId, phase)
    } finally {
      setBusy(null)
    }
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs text-slate-500">{label}</span>
      <Button variant="outline" disabled={busy != null || paused} onClick={() => run('pause')}>
        {busy === 'pause' ? '暂停中…' : '暂停'}
      </Button>
      <Button variant="outline" disabled={busy != null} onClick={() => run('resume')}>
        {busy === 'resume' ? '续跑中…' : '续跑'}
      </Button>
      <Button variant="outline" disabled={busy != null} onClick={() => run('restart')}>
        {busy === 'restart' ? '新跑中…' : '新跑'}
      </Button>
    </div>
  )
}

export default function ProjectDetailPage() {
  const { id } = useParams()
  const projectId = Number(id)
  const [project, setProject] = useState<Project | null>(null)
  const [events, setEvents] = useState<LogEvent[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [vulnsLoading, setVulnsLoading] = useState(false)
  const [tab, setTab] = useState<'logs' | 'reports' | 'vulns'>('logs')
  const [phaseFilter, setPhaseFilter] = useState('recon')
  const [hasOlder, setHasOlder] = useState(false)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [revealLimit, setRevealLimit] = useState(LOG_PAGE)
  const [streamFrom, setStreamFrom] = useState<number | null>(null)
  const [logSession, setLogSession] = useState<number | null>(null)
  const [displaySession, setDisplaySession] = useState(1)
  const [sessionCount, setSessionCount] = useState(1)
  const oldestRef = useRef(0)
  const fileEndRef = useRef(0)
  const phaseRef = useRef(phaseFilter)
  const syncedPhase = useRef(false)
  const loadingOlderRef = useRef(false)
  const atTopRef = useRef(false)
  const followLiveRef = useRef(true)
  const displaySessionRef = useRef(1)
  const sessionCountRef = useRef(1)

  const selectPhase = (p: string) => {
    if (p === phaseFilter) return
    setPhaseFilter(p)
    followLiveRef.current = true
    displaySessionRef.current = 1
    sessionCountRef.current = 1
    setDisplaySession(1)
    setSessionCount(1)
    setLogSession(null)
  }

  useEffect(() => {
    phaseRef.current = phaseFilter
  }, [phaseFilter])

  useEffect(() => {
    syncedPhase.current = false
    fileEndRef.current = 0
    oldestRef.current = 0
    followLiveRef.current = true
    displaySessionRef.current = 1
    sessionCountRef.current = 1
    setStreamFrom(null)
    setEvents([])
    setVulns([])
    setHasOlder(false)
    setRevealLimit(LOG_PAGE)
    setLogSession(null)
    setDisplaySession(1)
    setSessionCount(1)
  }, [projectId])

  useEffect(() => {
    if (!projectId) return
    let alive = true
    const refreshMeta = async () => {
      try {
        const p = await api.getProject(projectId)
        if (!alive) return
        setProject(p)
        if (!syncedPhase.current) {
          syncedPhase.current = true
          selectPhase(defaultPhaseTab(p.phase, p.status))
        }
      } catch {
        /* ignore transient */
      }
    }
    const stop = startVisibilityPoll(refreshMeta, 3000)
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
        const vs = await api.listVulns(projectId)
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
    if (!projectId) return
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
  }, [projectId, phaseFilter, logSession])

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
      source = new EventSource(`/api/projects/${projectId}/stream?${params.toString()}`)
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
            setProject((cur) =>
              cur
                ? {
                    ...cur,
                    status: nextStatus ?? cur.status,
                    phase: nextPhase ?? cur.phase,
                  }
                : cur,
            )
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

  if (!project) return <div className="text-slate-400">加载中…</div>

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link to="/" className="text-sm text-slate-400 hover:underline">
            ← 返回
          </Link>
          <h1 className="mt-1 text-2xl font-semibold">{project.name}</h1>
          <div className="mt-2">
            <PhaseFlow
              phase={project.phase}
              status={project.status}
              reconDone={project.recon_done}
              filesAudited={project.files_audited}
              filesSkipped={project.files_skipped}
              filesTotal={project.files_total}
              workerRounds={project.worker_rounds}
              vulnPending={project.vuln_pending}
              reconSubphases={project.recon_subphases}
              labSetupDone={project.lab_setup_done}
              manualLab={project.manual_lab}
              verifierEnabled={project.verifier_enabled}
              verifierPending={project.verifier_pending}
              onSelect={(pid) => {
                setTab('logs')
                if (pid !== 'done') selectPhase(pid)
              }}
            />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => api.pause(projectId)}>
            全部暂停
          </Button>
          <Button variant="outline" onClick={() => api.resume(projectId)}>
            全部续跑
          </Button>
          <Button variant="destructive" onClick={() => api.cancel(projectId)}>
            停止
          </Button>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
          <Badge variant="info">{project.status}</Badge>
          {project.status === 'paused' ? (
            <AuditModeSelect
              value={project.audit_mode}
              showHint={false}
              onValueChange={async (value) => {
                if (value === project.audit_mode) return
                try {
                  const next = await api.updateProject(projectId, { audit_mode: value })
                  setProject(next)
                } catch {
                  /* ignore */
                }
              }}
            />
          ) : (
            <Badge variant="outline" title={formatAuditModeHint(project.audit_mode)}>
              {formatAuditMode(project.audit_mode)}
            </Badge>
          )}
          <span>tokens {formatTokens(project.tokens_total)}</span>
          <span>{formatFileProgress(project)}</span>
          <span>
            洞 确认{project.vuln_confirmed} / 待审{project.vuln_pending} / 误报{project.vuln_false_positive}
          </span>
        </div>
        <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">
          {formatAuditModeHint(project.audit_mode)}
          {project.status === 'paused' ? ' 暂停时可更改，续跑后按新规则生效。' : ''}
        </p>
        {project.manual_lab ? (
          <ManualLabPromptEditor
            prompt={project.manual_lab_prompt || ''}
            onSave={async (text) => {
              const next = await api.updateProject(projectId, { manual_lab_prompt: text })
              setProject(next)
            }}
          />
        ) : null}
        <VerifierToggle
          enabled={Boolean(project.verifier_enabled)}
          onEnabledChange={async (enabled) => {
            if (enabled === Boolean(project.verifier_enabled)) return
            try {
              const next = await api.updateProject(projectId, { verifier_enabled: enabled })
              setProject(next)
            } catch {
              /* ignore */
            }
          }}
        />
      </div>

      <div className="flex gap-2">
        <Button variant={tab === 'logs' ? 'default' : 'outline'} onClick={() => setTab('logs')}>
          阶段日志
        </Button>
        <Button variant={tab === 'reports' ? 'default' : 'outline'} onClick={() => setTab('reports')}>
          阶段报告
        </Button>
        <Button variant={tab === 'vulns' ? 'default' : 'outline'} onClick={() => setTab('vulns')}>
          本项目漏洞
        </Button>
      </div>

      {tab === 'reports' ? (
        <Suspense fallback={<div className="text-sm text-muted-foreground">加载报告…</div>}>
          <PhaseReportsPanel projectId={projectId} initialPhase={controlPhaseOf(phaseFilter)} />
        </Suspense>
      ) : null}

      {tab === 'logs' ? (
        <Card>
          <CardContent className="p-3">
          <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
            <div className="vh-phase-tabs">
              {PHASE_TABS.map(([k, label]) => (
                <div key={k} className="vh-phase-branch">
                  <Button
                    variant={controlPhaseOf(phaseFilter) === k ? 'default' : 'outline'}
                    onClick={() => selectPhase(k)}
                  >
                    {label}
                  </Button>
                  {k === 'recon' ? (
                    <div className="vh-phase-subs">
                      {RECON_LOG_TABS.map(([sk, slabel, subId]) => {
                        const done = Boolean(project.recon_subphases?.find((s) => s.id === subId)?.done)
                        return (
                          <Button
                            key={sk}
                            className="h-6 px-2 text-[11px]"
                            variant={phaseFilter === sk ? 'default' : 'outline'}
                            onClick={() => selectPhase(sk)}
                          >
                            {slabel}
                            {done ? ' ✓' : ' ○'}
                          </Button>
                        )
                      })}
                    </div>
                  ) : null}
                  {k === 'worker' ? (
                    <div className="vh-phase-subs">
                      {WORKER_LOG_TABS.map(([sk, slabel]) => (
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
                      {REVIEWER_LOG_TABS.map(([sk, slabel]) => (
                        <Button
                          key={sk}
                          className="h-6 px-2 text-[11px]"
                          variant={phaseFilter === sk ? 'default' : 'outline'}
                          onClick={() => selectPhase(sk)}
                        >
                          {sk === 'reviewer-lab' && project.manual_lab ? '人工靶场' : slabel}
                          {sk === 'reviewer-lab' ? (project.lab_setup_done ? ' ✓' : ' ○') : ''}
                        </Button>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
            <PhaseRunControls projectId={projectId} phase={controlPhaseOf(phaseFilter)} project={project} />
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
            onSessionChange={(n) => {
              followLiveRef.current = n == null || n >= sessionCountRef.current
              const next = n ?? sessionCountRef.current
              displaySessionRef.current = next
              setDisplaySession(next)
              setLogSession(n)
            }}
          />
          </CardContent>
        </Card>
      ) : tab === 'vulns' ? (
        <Card className="gap-0 divide-y divide-border py-0">
          <VulnGroupList
            vulns={vulns}
            emptyText={vulnsLoading ? '加载漏洞…' : '暂无漏洞'}
          />
        </Card>
      ) : null}
    </div>
  )
}
