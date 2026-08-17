import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { SearchIcon, XIcon } from 'lucide-react'
import { api, type Project, type Vuln, type VulnDetail, type VulnTrackingStatus } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import VulnGroupList from '../components/VulnGroupList'
import { filterVulnGroups, groupVulnsByRootCause, vulnMatchesQuery, type VulnTierFilter } from '../lib/vulnGroups'
import {
  formatAttackSurface,
  formatDateTime,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
  formatTrackingStatus,
  formatVerifierStatus,
  severityScoreBadgeClass,
} from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import VulnFollowUpPanel from '../components/VulnFollowUpPanel'

const MarkdownView = lazy(() => import('../components/MarkdownView'))

const TIER_FILTER_LABEL: Record<VulnTierFilter, string> = {
  all: '全部分层',
  cve_candidate: '有 CVE 价值',
  low_impact: '低危害难利用',
  duplicate_grouped: '同根因重复',
  untiered: '未分层',
}

const TRACKING_FILTER_LABEL: Record<'all' | VulnTrackingStatus, string> = {
  all: '全部标记',
  none: '未标记',
  submitted: '已提交',
  ignored: '已忽略',
}

export default function VulnsPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const detailId = id ? Number(id) : null
  const [filter, setFilter] = useState<'all' | 'confirmed' | 'false_positive' | 'pending_review'>('all')
  const [surfaceFilter, setSurfaceFilter] = useState<'all' | 'frontend' | 'backend'>('all')
  const [tierFilter, setTierFilter] = useState<VulnTierFilter>('all')
  const [trackingFilter, setTrackingFilter] = useState<'all' | VulnTrackingStatus>('all')
  const [projectId, setProjectId] = useState<number | undefined>()
  const [projects, setProjects] = useState<Project[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [detail, setDetail] = useState<VulnDetail | null>(null)
  const [selected, setSelected] = useState<number[]>([])
  const [marking, setMarking] = useState(false)
  const [search, setSearch] = useState('')

  const projectNameById = useMemo(() => {
    const map = new Map<number, string>()
    for (const p of projects) map.set(p.id, p.name)
    return map
  }, [projects])

  const refresh = () =>
    api
      .listVulns(
        projectId,
        filter === 'all' ? undefined : filter,
        surfaceFilter === 'all' ? undefined : surfaceFilter,
        undefined,
        undefined,
        trackingFilter === 'all' ? undefined : trackingFilter,
      )
      .then(setVulns)
      .catch(() => {})

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
  }, [])

  useEffect(() => startVisibilityPoll(refresh, 5000), [filter, projectId, surfaceFilter, trackingFilter])

  useEffect(() => {
    setSelected([])
  }, [filter, projectId, surfaceFilter, tierFilter, trackingFilter])

  useEffect(() => {
    if (!detailId) {
      setDetail(null)
      return
    }
    api.getVuln(detailId).then(setDetail).catch(() => setDetail(null))
  }, [detailId])

  const searchedVulns = useMemo(
    () => vulns.filter((v) => vulnMatchesQuery(v, search, projectNameById)),
    [vulns, search, projectNameById],
  )
  const visibleVulns = useMemo(
    () =>
      filterVulnGroups(groupVulnsByRootCause(searchedVulns), tierFilter).flatMap((g) => [
        g.primary,
        ...g.others,
      ]),
    [searchedVulns, tierFilter],
  )
  const cveCandidateIds = useMemo(
    () => searchedVulns.filter((v) => v.submission_tier === 'cve_candidate').map((v) => v.id),
    [searchedVulns],
  )
  const detailSurface = formatAttackSurface(detail?.attack_surface, detail?.required_account)
  const detailScore = formatSeverityScore(detail?.severity_score)
  const detailTier = formatSubmissionTier(detail?.submission_tier)
  const detailTracking = formatTrackingStatus(detail?.tracking_status)
  const detailVerifier = formatVerifierStatus(detail?.verifier_status)
  const detailProject =
    detail?.project_name ||
    (detail ? projectNameById.get(detail.project_id) : undefined) ||
    (detail ? `项目 ${detail.project_id}` : '')
  const projectFilterLabel = projectId == null ? '全部项目' : projectNameById.get(projectId) || `项目 ${projectId}`
  const surfaceFilterLabel =
    surfaceFilter === 'frontend' ? '前台漏洞' : surfaceFilter === 'backend' ? '后台漏洞' : '全部前后台'

  async function downloadIds(ids: number[], filename: string) {
    if (!ids.length) return
    const blob = await api.downloadVulns(ids)
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
  }

  async function download() {
    const ids = selected.length ? selected : visibleVulns.map((v) => v.id)
    await downloadIds(ids, 'vulns.zip')
  }

  async function downloadCveCandidates() {
    const ids = selected.length
      ? selected.filter((id) => cveCandidateIds.includes(id))
      : cveCandidateIds
    await downloadIds(ids, 'vulns-cve-candidates.zip')
  }

  function applyTracking(updated: Array<Pick<Vuln, 'id' | 'tracking_status'>>) {
    const byId = new Map(updated.map((v) => [v.id, (v.tracking_status ?? 'none') as VulnTrackingStatus]))
    setVulns((prev) =>
      prev.map((v) => {
        const next = byId.get(v.id)
        return next == null ? v : { ...v, tracking_status: next }
      }),
    )
    setDetail((cur) => {
      if (!cur) return cur
      const next = byId.get(cur.id)
      return next == null ? cur : { ...cur, tracking_status: next }
    })
  }

  async function markIds(ids: number[], tracking_status: VulnTrackingStatus) {
    if (!ids.length || marking) return
    setMarking(true)
    try {
      if (ids.length === 1) {
        applyTracking([await api.updateVulnTracking(ids[0], tracking_status)])
      } else {
        applyTracking(await api.markVulns(ids, tracking_status))
      }
      await refresh()
    } catch {
      /* ignore transient */
    } finally {
      setMarking(false)
    }
  }

  async function markSelected(tracking_status: VulnTrackingStatus) {
    await markIds(selected, tracking_status)
  }

  async function markDetail(tracking_status: VulnTrackingStatus) {
    if (!detail) return
    await markIds([detail.id], tracking_status)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">漏洞产出</h1>
          <p className="text-sm text-slate-400">
            按项目、状态、价值分层与提交标记筛选；同根因报告折叠在危害最大的条目下。
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('submitted')}
          >
            标记已提交
          </Button>
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('ignored')}
          >
            标记已忽略
          </Button>
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('none')}
          >
            取消标记
          </Button>
          <Button variant="outline" onClick={downloadCveCandidates} disabled={!cveCandidateIds.length && !selected.length}>
            仅下载有 CVE 价值
          </Button>
          <Button onClick={download}>批量下载</Button>
        </div>
      </div>

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pr-8 pl-8"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="搜索标题、路径、类型、编号、项目…"
          aria-label="搜索漏洞"
        />
        {search ? (
          <button
            type="button"
            className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
            aria-label="清除搜索"
            onClick={() => setSearch('')}
          >
            <XIcon className="size-4" />
          </button>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={projectId == null ? '__all__' : String(projectId)}
          onValueChange={(value) => {
            if (value == null) return
            setProjectId(value === '__all__' ? undefined : Number(value))
          }}
        >
          <SelectTrigger className="w-auto min-w-52">
            <SelectValue>{projectFilterLabel}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            <SelectItem value="__all__">全部项目</SelectItem>
            {projects.map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={surfaceFilter} onValueChange={(value) => setSurfaceFilter(value as typeof surfaceFilter)}>
          <SelectTrigger className="w-auto min-w-36">
            <SelectValue>{surfaceFilterLabel}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            <SelectItem value="all">全部前后台</SelectItem>
            <SelectItem value="frontend">前台漏洞</SelectItem>
            <SelectItem value="backend">后台漏洞</SelectItem>
          </SelectContent>
        </Select>
        <Select value={tierFilter} onValueChange={(value) => setTierFilter(value as VulnTierFilter)}>
          <SelectTrigger className="w-auto min-w-36">
            <SelectValue>{TIER_FILTER_LABEL[tierFilter]}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            {(Object.keys(TIER_FILTER_LABEL) as VulnTierFilter[]).map((k) => (
              <SelectItem key={k} value={k}>
                {TIER_FILTER_LABEL[k]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={trackingFilter}
          onValueChange={(value) => {
            if (value == null) return
            setTrackingFilter(value as typeof trackingFilter)
          }}
        >
          <SelectTrigger className="w-auto min-w-32">
            <SelectValue>{TRACKING_FILTER_LABEL[trackingFilter]}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            {(Object.keys(TRACKING_FILTER_LABEL) as Array<keyof typeof TRACKING_FILTER_LABEL>).map((k) => (
              <SelectItem key={k} value={k}>
                {TRACKING_FILTER_LABEL[k]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(
          [
            ['all', '全部'],
            ['confirmed', '已确认'],
            ['false_positive', '误报'],
            ['pending_review', '待审'],
          ] as const
        ).map(([k, label]) => (
          <Button key={k} variant={filter === k ? 'default' : 'outline'} onClick={() => setFilter(k)}>
            {label}
          </Button>
        ))}
      </div>

      <Card className="max-h-[calc(100vh-13rem)] gap-0 divide-y divide-border overflow-auto py-0">
        <VulnGroupList
          vulns={searchedVulns}
          tierFilter={tierFilter}
          activeId={detailId}
          selectedIds={selected}
          expandAll={Boolean(search.trim())}
          emptyText={search.trim() ? '无匹配漏洞' : '暂无数据'}
          onToggleSelect={(id, checked) =>
            setSelected((prev) => (checked ? [...prev, id] : prev.filter((x) => x !== id)))
          }
          projectNameById={projectNameById}
        />
      </Card>

      <Dialog
        open={detailId != null}
        onOpenChange={(open) => {
          if (!open) navigate('/vulns', { replace: true })
        }}
      >
        <DialogContent className="flex max-h-[min(90vh,52rem)] w-full max-w-[calc(100%-2rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-4xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle className="text-lg leading-snug font-semibold">
              {detail?.title || '漏洞详情'}
            </DialogTitle>
            <DialogDescription>
              {detail ? `${detailProject} · 产出时间 ${formatDateTime(detail.created_at)}` : '加载报告…'}
            </DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto px-5 py-4">
            {detail ? (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="outline">{detail.vuln_type}</Badge>
                  <Badge variant="warning">{formatSeverity(detail.severity)}</Badge>
                  {detailScore ? (
                    <Badge variant="outline" className={severityScoreBadgeClass(detail.severity_score)}>
                      {detailScore}
                    </Badge>
                  ) : null}
                  <Badge variant={detail.submission_tier === 'cve_candidate' ? 'info' : 'outline'}>{detailTier}</Badge>
                  <Badge variant="info">{detail.status}</Badge>
                  {detail.tracking_status === 'submitted' || detail.tracking_status === 'ignored' ? (
                    <Badge variant={detail.tracking_status === 'submitted' ? 'info' : 'outline'}>{detailTracking}</Badge>
                  ) : null}
                  {detail.evidence_level && detail.evidence_level !== 'static_only' ? (
                    <Badge variant="outline">{detail.evidence_level}</Badge>
                  ) : null}
                  {detailSurface ? <Badge variant="info">{detailSurface}</Badge> : null}
                  {detailVerifier ? (
                    <Badge
                      variant={
                        detail.verifier_status === 'verified'
                          ? 'success'
                          : detail.verifier_status === 'failed'
                            ? 'destructive'
                            : 'outline'
                      }
                    >
                      {detailVerifier}
                    </Badge>
                  ) : null}
                  {detail.verifier_verified_url ? (
                    <span className="text-xs text-slate-400">{detail.verifier_verified_url}</span>
                  ) : null}
                </div>
                {detail.verifier_status === 'skipped' ? (
                  <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                    未做互联网复测。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的类型不会打互联网目标；其它原因见下方报告「互联网验证」。
                  </div>
                ) : null}
                {detail.verifier_status === 'verified' ? (
                  <div className="space-y-2 rounded border border-emerald-900/50 bg-emerald-950/20 px-3 py-2">
                    <div className="text-xs font-medium text-emerald-300/90">互联网复现证据</div>
                    <div className="space-y-1 text-sm">
                      <div className="text-xs text-slate-400">打通目标</div>
                      <div className="break-all text-slate-200">
                        {detail.verifier_verified_url || '（未记录 URL）'}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">使用的 PoC</div>
                      <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs text-slate-200">
                        {detail.verifier_poc || '（未记录对该目标发出的请求）'}
                      </pre>
                    </div>
                    <div className="space-y-1">
                      <div className="text-xs text-slate-400">实际响应</div>
                      <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs text-slate-200">
                        {detail.verifier_response || '（未记录该目标的响应）'}
                      </pre>
                    </div>
                  </div>
                ) : null}
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant={detail.tracking_status === 'submitted' ? 'default' : 'outline'}
                    disabled={marking}
                    onClick={() =>
                      markDetail(detail.tracking_status === 'submitted' ? 'none' : 'submitted')
                    }
                  >
                    {detail.tracking_status === 'submitted' ? '取消已提交' : '标记已提交'}
                  </Button>
                  <Button
                    size="sm"
                    variant={detail.tracking_status === 'ignored' ? 'default' : 'outline'}
                    disabled={marking}
                    onClick={() => markDetail(detail.tracking_status === 'ignored' ? 'none' : 'ignored')}
                  >
                    {detail.tracking_status === 'ignored' ? '取消已忽略' : '标记已忽略'}
                  </Button>
                </div>
                {detail.submission_reason ? (
                  <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                    <div className="text-xs text-slate-400">分层理由</div>
                    <div>{detail.submission_reason}</div>
                    {detail.root_cause_key ? (
                      <div className="mt-1 text-xs text-slate-400">根因键：{detail.root_cause_key}</div>
                    ) : null}
                  </div>
                ) : null}
                {detail.merged_into_id ? (
                  <div className="rounded border border-cyan-900/50 bg-cyan-950/30 px-3 py-2 text-sm text-cyan-200/90">
                    已并入主报告{' '}
                    <Link className="underline" to={`/vulns/${detail.merged_into_id}`}>
                      #{detail.merged_into_id}
                    </Link>
                  </div>
                ) : null}
                {detail.merged_from_ids && detail.merged_from_ids.length > 0 ? (
                  <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                    <div className="text-xs text-slate-400">已并入本报告的条目</div>
                    <div className="mt-1 flex flex-wrap gap-2">
                      {detail.merged_from_ids.map((mid) => (
                        <Link key={mid} className="text-cyan-300 underline" to={`/vulns/${mid}`}>
                          #{mid}
                        </Link>
                      ))}
                    </div>
                  </div>
                ) : null}
                <Suspense fallback={<div className="text-sm text-muted-foreground">加载报告…</div>}>
                  <MarkdownView content={detail.report_md || detail.source_sink || '_无报告_'} />
                </Suspense>
                {detail.http_request ? (
                  <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.http_request}</pre>
                ) : null}
                {detail.poc_code ? (
                  <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.poc_code}</pre>
                ) : null}
                <VulnFollowUpPanel vulnId={detail.id} />
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">加载报告…</div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
