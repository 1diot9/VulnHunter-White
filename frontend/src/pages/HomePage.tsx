import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronLeftIcon, ChevronRightIcon, Loader2Icon, PlusIcon, SearchIcon, XIcon } from 'lucide-react'
import { api, formatProjectsListError, type Project, type ProjectRunStatusCounts } from '../api'
import { CreateProjectDialog } from '../components/CreateProjectDialog'
import { DeleteProjectButton } from '../components/DeleteProjectButton'
import { GithubLink } from '../components/GithubLink'
import { ProjectRunButtons } from '../components/ProjectRunButtons'
import { normalizeDynamicVerifyMode } from '../components/DynamicVerifyToggle'
import PhaseFlow from '../components/PhaseFlow'
import { WeightExtBadges } from '../components/WeightExtBadges'
import LlmThreadUsageBar from '../components/LlmThreadUsageBar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { githubRepoHref } from '../lib/github'
import {
  overlayProjectRun,
  PROJECT_LIST_CHANGED_EVENT,
  projectPreviewCacheKey,
  readJsonCache,
  rememberProjectRun,
  writeJsonCache,
} from '../lib/listCache'
import { formatAuditMode, formatDateTime, formatMiningPaths, formatMiningProgress, formatProjectRunStatus, formatTargetKind, formatTokenUsage, projectRunBucket } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const PAGE_SIZE = 5

const EMPTY_STATUS_COUNTS: ProjectRunStatusCounts = {
  all: 0,
  running: 0,
  paused: 0,
  completed: 0,
}

function CreateProjectButton({ onClick }: { onClick: () => void }) {
  return (
    <Button
      size="lg"
      className="h-11 shrink-0 gap-2 px-5 text-base font-semibold shadow-lg shadow-primary/25 ring-2 ring-primary/40"
      onClick={onClick}
    >
      <PlusIcon className="size-5" />
      创建项目
    </Button>
  )
}

type RunStatusFilter = 'all' | 'running' | 'paused' | 'completed'

const RUN_STATUS_FILTERS: { key: RunStatusFilter; label: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'running', label: '运行中' },
  { key: 'paused', label: '已暂停' },
  { key: 'completed', label: '已完成' },
]

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [total, setTotal] = useState(0)
  const [statusCounts, setStatusCounts] = useState<ProjectRunStatusCounts>(EMPTY_STATUS_COUNTS)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<RunStatusFilter>('all')
  const [createOpen, setCreateOpen] = useState(false)
  const etagRef = useRef('')
  const etagQueryRef = useRef('')
  const loadGenRef = useRef(0)

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const pageRef = useRef(page)
  pageRef.current = page

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput), 300)
    return () => window.clearTimeout(timer)
  }, [searchInput])

  const applyListData = useCallback((data: Awaited<ReturnType<typeof api.listProjects>>, fromNetwork = false) => {
    const raw = fromNetwork ? data.items : data.items.map(overlayProjectRun)
    const items =
      statusFilter === 'all'
        ? raw
        : raw.filter((item) => projectRunBucket(item.status, item.project_paused) === statusFilter)
    if (fromNetwork) {
      for (const item of data.items) rememberProjectRun(item)
    }
    setProjects(items)
    setTotal(data.total)
    setStatusCounts(data.status_counts)
    setError('')
    for (const item of items) {
      writeJsonCache(projectPreviewCacheKey(item.id), item)
    }
    const nextPageCount = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
    if (pageRef.current >= nextPageCount) setPage(Math.max(0, nextPageCount - 1))
  }, [statusFilter])

  const fetchProjects = useCallback(
    (showLoading = false) => {
      const cacheKey = `vh:projects:${PAGE_SIZE}:${page}:${search}:${statusFilter}`
      etagRef.current = ''
      etagQueryRef.current = cacheKey
      if (showLoading) setLoading(true)
      return api
        .listProjects({
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
          q: search,
          run_status: statusFilter,
        })
        .then((data) => {
          if (data.notModified) return
          etagRef.current = data.etag || ''
          etagQueryRef.current = cacheKey
          applyListData(data, true)
          writeJsonCache(cacheKey, data)
        })
        .catch((e) => {
          const cached = readJsonCache(cacheKey)
          setError(formatProjectsListError(e, Boolean(cached)))
        })
        .finally(() => {
          if (showLoading) setLoading(false)
        })
    },
    [page, search, statusFilter, applyListData],
  )

  useEffect(() => {
    let cancelled = false
    const gen = ++loadGenRef.current
    const cacheKey = `vh:projects:${PAGE_SIZE}:${page}:${search}:${statusFilter}`
    const cached = readJsonCache<Awaited<ReturnType<typeof api.listProjects>>>(cacheKey)
    const hasCache = Boolean(cached && !cached.notModified && !cached.unchanged)
    if (etagQueryRef.current !== cacheKey) {
      etagRef.current = hasCache && cached?.etag ? cached.etag : ''
      etagQueryRef.current = cacheKey
    }
    if (hasCache && cached) {
      applyListData(cached)
      setLoading(false)
    } else {
      setLoading(true)
    }

    const load = () =>
      api
        .listProjects(
          {
            limit: PAGE_SIZE,
            offset: page * PAGE_SIZE,
            q: search,
            run_status: statusFilter,
          },
          { etag: etagQueryRef.current === cacheKey ? etagRef.current || undefined : undefined },
        )
        .then((data) => {
          if (cancelled) return
          if (data.notModified) return
          etagRef.current = data.etag || ''
          etagQueryRef.current = cacheKey
          applyListData(data, true)
          writeJsonCache(cacheKey, data)
        })
        .catch((e) => {
          if (!cancelled) setError(formatProjectsListError(e, hasCache))
        })
        .finally(() => {
          if (loadGenRef.current === gen) setLoading(false)
        })

    const stopPoll = startVisibilityPoll(() => {
      if (cancelled) return
      return load()
    }, 4000)

    return () => {
      cancelled = true
      stopPoll()
    }
  }, [page, search, statusFilter, applyListData])

  useEffect(() => {
    const onListChanged = () => {
      etagRef.current = ''
      const cacheKey = `vh:projects:${PAGE_SIZE}:${page}:${search}:${statusFilter}`
      const cached = readJsonCache<Awaited<ReturnType<typeof api.listProjects>>>(cacheKey)
      if (cached && !cached.notModified && !cached.unchanged) applyListData(cached)
      void fetchProjects(false)
    }
    window.addEventListener(PROJECT_LIST_CHANGED_EVENT, onListChanged)
    return () => window.removeEventListener(PROJECT_LIST_CHANGED_EVENT, onListChanged)
  }, [page, search, statusFilter, applyListData, fetchProjects])

  return (
    <div className="w-full space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">审计项目</h1>
          <p className="mt-1 text-sm text-slate-400">导入 GitHub 仓库或源码 zip，启动白盒审计。</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <LlmThreadUsageBar />
          <CreateProjectButton onClick={() => setCreateOpen(true)} />
        </div>
      </div>

      <CreateProjectDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          setPage(0)
          fetchProjects(true)
        }}
      />

      <div className="space-y-3">
        <div className="relative">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="pr-8 pl-8"
            value={searchInput}
            onChange={(e) => {
              setPage(0)
              setSearchInput(e.target.value)
            }}
            placeholder="搜索项目名称、仓库、模式、模型、状态…"
            aria-label="搜索审计项目"
          />
          {searchInput ? (
            <button
              type="button"
              className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
              aria-label="清除搜索"
              onClick={() => {
                setPage(0)
                setSearchInput('')
              }}
            >
              <XIcon className="size-4" />
            </button>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="按运行状态筛选">
          {RUN_STATUS_FILTERS.map(({ key, label }) => (
            <Button
              key={key}
              variant={statusFilter === key ? 'default' : 'outline'}
              onClick={() => {
                if (key === statusFilter) return
                setPage(0)
                setStatusFilter(key)
                setProjects([])
                setLoading(true)
              }}
            >
              {label} {statusCounts[key]}
            </Button>
          ))}
        </div>
      </div>

      {error ? <p className="text-sm text-red-300">{error}</p> : null}

      <div className="flex w-full min-h-[12rem] flex-col gap-3">
        {loading ? (
          <Card className="w-full">
            <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground">
              <Loader2Icon className="size-8 animate-spin" aria-hidden />
              <span className="text-sm">加载项目列表…</span>
            </CardContent>
          </Card>
        ) : null}
        {!loading
          ? projects.map((p) => {
          const runStatus = formatProjectRunStatus(p.status, p.project_paused)
          return (
          <Card key={p.id} className="w-full">
            <CardHeader>
              <div className="min-w-0">
                <CardTitle>
                  <Link to={`/projects/${p.id}`} className="hover:underline">
                    {p.name}
                  </Link>
                </CardTitle>
                <CardDescription className="mt-1 flex min-w-0 flex-wrap items-center gap-x-1.5 text-xs">
                  <span>{formatTargetKind(p.target_kind)}</span>
                  <span>·</span>
                  <span>{formatAuditMode(p.audit_mode, p.custom_audit_mode_name)}</span>
                  <span>·</span>
                  <span>{p.llm_model || '全局模型'}</span>
                  <span>·</span>
                  <span>{formatMiningPaths(p)}</span>
                  <span>·</span>
                  {githubRepoHref(p) ? (
                    <GithubLink project={p} className="min-w-0" />
                  ) : (
                    <span className="truncate">{p.identity || p.source_url || p.source_type}</span>
                  )}
                  <span>·</span>
                  <span>{formatDateTime(p.created_at)}</span>
                </CardDescription>
              </div>
              <CardAction>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <GithubLink project={p} variant="button" />
                  <Badge
                    variant={
                      runStatus === '已完成'
                        ? 'success'
                        : runStatus === '已停止'
                          ? 'destructive'
                          : runStatus === '已暂停'
                            ? 'warning'
                            : 'info'
                    }
                  >
                    {runStatus}
                  </Badge>
                  <ProjectRunButtons project={p} />
                  <DeleteProjectButton
                    projectId={p.id}
                    projectName={p.name}
                    size="sm"
                    onDeleted={() => fetchProjects(true)}
                  />
                </div>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-3">
              <PhaseFlow
                phase={p.phase}
                status={p.status}
                reconDone={p.recon_done}
                filesAudited={p.files_audited}
                filesSkipped={p.files_skipped}
                filesTotal={p.files_total}
                filesWeight100={p.files_weight100}
                filesWeight100Audited={p.files_weight100_audited}
                workerRounds={p.worker_rounds}
                vulnPending={p.vuln_pending}
                reconSubphases={p.recon_subphases}
                labSetupDone={p.lab_setup_done}
                manualLab={Boolean(p.manual_lab)}
                dynamicVerifyEnabled={p.dynamic_verify_enabled}
                dynamicVerifyMode={normalizeDynamicVerifyMode(p.dynamic_verify_mode, p.dynamic_verify_enabled)}
                verifierEnabled={p.verifier_enabled}
                verifierPending={p.verifier_pending}
                attackChainEnabled={p.attack_chain_enabled}
                attackChainDone={p.attack_chain_done}
                heuristicEnabled={p.heuristic_enabled}
                heuristicLite={p.heuristic_lite}
                fastEnabled={p.fast_enabled}
                fastQueueFrozen={p.fast_queue_frozen}
                sinksQueued={p.sinks_queued}
                sinksDone={p.sinks_done}
                bypassEnabled={p.bypass_enabled}
                bypassQueueFrozen={p.bypass_queue_frozen}
                bypassQueued={p.bypass_queued}
                bypassDone={p.bypass_done}
                unconstrainedEnabled={p.unconstrained_enabled}
                unconstrainedDone={p.unconstrained_done}
              />
              <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                <span>确认 {p.vuln_confirmed}</span>
                <span>待审 {p.vuln_pending}</span>
                <span>误报 {p.vuln_false_positive}</span>
                <span>{formatMiningProgress(p)}</span>
                <span>{formatTokenUsage(p)}</span>
              </div>
              <WeightExtBadges exts={p.weight_exts} />
              {p.error ? <p className="text-xs text-red-300">{p.error}</p> : null}
            </CardContent>
          </Card>
          )
        })
          : null}
        {!loading && projects.length === 0 ? (
          <Card className="w-full">
            <CardContent className="flex flex-col items-start gap-3 py-8 text-sm text-muted-foreground">
              {searchInput.trim() || statusFilter !== 'all' ? (
                '无匹配项目'
              ) : (
                <>
                  <p>暂无项目。点击「创建项目」导入 GitHub 仓库或源码 zip。</p>
                  <CreateProjectButton onClick={() => setCreateOpen(true)} />
                </>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>

      {total > PAGE_SIZE ? (
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
          <span>
            第 {page + 1} / {pageCount} 页，共 {total} 项
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={loading || page <= 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              aria-label="上一页"
            >
              <ChevronLeftIcon className="size-4" />
              上一页
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={loading || page + 1 >= pageCount}
              onClick={() => setPage((p) => p + 1)}
              aria-label="下一页"
            >
              下一页
              <ChevronRightIcon className="size-4" />
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
