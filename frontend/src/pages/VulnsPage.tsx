import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, type Project, type Vuln, type VulnDetail } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  cn,
  formatAttackSurface,
  formatDateTime,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
  severityScoreBadgeClass,
} from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import VulnFollowUpPanel from '../components/VulnFollowUpPanel'

const STATUS_LABEL: Record<string, string> = {
  pending_review: '待审',
  confirmed: '已确认',
  false_positive: '误报',
  static_only: '仅静态',
  returned: '已打回',
}

type TierFilter =
  | 'all'
  | 'cve_candidate'
  | 'advisory_only'
  | 'hardening'
  | 'duplicate_grouped'
  | 'needs_more_evidence'
  | 'untiered'

const TIER_FILTER_LABEL: Record<TierFilter, string> = {
  all: '全部分层',
  cve_candidate: 'CVE 候选',
  advisory_only: '仅公告',
  hardening: '加固建议',
  duplicate_grouped: '同根因重复',
  needs_more_evidence: '证据不足',
  untiered: '未分层',
}

const MarkdownView = lazy(() => import('../components/MarkdownView'))

export default function VulnsPage() {
  const { id } = useParams()
  const detailId = id ? Number(id) : null
  const [filter, setFilter] = useState<'all' | 'confirmed' | 'false_positive' | 'pending_review'>('all')
  const [surfaceFilter, setSurfaceFilter] = useState<'all' | 'frontend' | 'backend'>('all')
  const [tierFilter, setTierFilter] = useState<TierFilter>('all')
  const [projectId, setProjectId] = useState<number | undefined>()
  const [projects, setProjects] = useState<Project[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [detail, setDetail] = useState<VulnDetail | null>(null)
  const [selected, setSelected] = useState<number[]>([])

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
        tierFilter === 'all' ? undefined : tierFilter,
      )
      .then(setVulns)
      .catch(() => {})

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
  }, [])

  useEffect(() => startVisibilityPoll(refresh, 5000), [filter, projectId, surfaceFilter, tierFilter])

  useEffect(() => {
    setSelected([])
  }, [filter, projectId, surfaceFilter, tierFilter])

  useEffect(() => {
    if (!detailId) {
      setDetail(null)
      return
    }
    api.getVuln(detailId).then(setDetail).catch(() => setDetail(null))
  }, [detailId])

  const filtered = useMemo(() => vulns, [vulns])
  const cveCandidateIds = useMemo(
    () => filtered.filter((v) => v.submission_tier === 'cve_candidate').map((v) => v.id),
    [filtered],
  )
  const detailSurface = formatAttackSurface(detail?.attack_surface, detail?.required_account)
  const detailScore = formatSeverityScore(detail?.severity_score)
  const detailTier = formatSubmissionTier(detail?.submission_tier)
  const detailProject =
    detail?.project_name ||
    (detail ? projectNameById.get(detail.project_id) : undefined) ||
    (detail ? `项目 ${detail.project_id}` : '')
  const projectFilterLabel = projectId == null ? '全部项目' : projectNameById.get(projectId) || `项目 ${projectId}`
  const surfaceFilterLabel =
    surfaceFilter === 'frontend' ? '前台漏洞' : surfaceFilter === 'backend' ? '后台漏洞' : '全部前后台'
  const showDetailPane = detailId != null

  async function downloadIds(ids: number[], filename: string) {
    if (!ids.length) return
    const blob = await api.downloadVulns(ids)
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
  }

  async function download() {
    const ids = selected.length ? selected : filtered.map((v) => v.id)
    await downloadIds(ids, 'vulns.zip')
  }

  async function downloadCveCandidates() {
    const ids = selected.length
      ? selected.filter((id) => cveCandidateIds.includes(id))
      : cveCandidateIds
    await downloadIds(ids, 'vulns-cve-candidates.zip')
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">漏洞产出</h1>
          <p className="text-sm text-slate-400">按项目、状态与提交分层筛选；可单独下载 CVE 候选。</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={downloadCveCandidates} disabled={!cveCandidateIds.length && !selected.length}>
            仅下载 CVE 候选
          </Button>
          <Button onClick={download}>批量下载</Button>
        </div>
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
        <Select value={tierFilter} onValueChange={(value) => setTierFilter(value as TierFilter)}>
          <SelectTrigger className="w-auto min-w-36">
            <SelectValue>{TIER_FILTER_LABEL[tierFilter]}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            {(Object.keys(TIER_FILTER_LABEL) as TierFilter[]).map((k) => (
              <SelectItem key={k} value={k}>
                {TIER_FILTER_LABEL[k]}
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

      <div
        className={cn(
          'grid items-start gap-4',
          showDetailPane ? 'lg:grid-cols-[minmax(16rem,18rem)_minmax(0,1fr)]' : 'lg:grid-cols-1',
        )}
      >
        <Card className="max-h-[calc(100vh-13rem)] gap-0 divide-y divide-border overflow-auto py-0">
          {filtered.map((v) => {
            const surface = formatAttackSurface(v.attack_surface, v.required_account)
            const score = formatSeverityScore(v.severity_score)
            const tier = formatSubmissionTier(v.submission_tier)
            const projectName = v.project_name || projectNameById.get(v.project_id) || `项目 ${v.project_id}`
            return (
              <div
                key={v.id}
                className={cn(
                  'flex items-start gap-2 px-2.5 py-2.5',
                  detailId === v.id && 'bg-muted',
                )}
              >
                <Checkbox
                  className="mt-1 shrink-0"
                  checked={selected.includes(v.id)}
                  onCheckedChange={(checked) =>
                    setSelected((prev) =>
                      checked === true ? [...prev, v.id] : prev.filter((x) => x !== v.id),
                    )
                  }
                />
                <Link to={`/vulns/${v.id}`} className="min-w-0 flex-1 hover:underline">
                  <div className="break-words font-medium leading-snug">{v.title}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <Badge
                      variant={
                        v.status === 'confirmed' || v.status === 'static_only'
                          ? 'success'
                          : v.status === 'false_positive'
                            ? 'destructive'
                            : 'warning'
                      }
                    >
                      {STATUS_LABEL[v.status] || v.status}
                      {v.evidence_level === 'static_only' ? ' · 静态' : ''}
                    </Badge>
                    {score ? (
                      <Badge variant="outline" className={severityScoreBadgeClass(v.severity_score)}>
                        {score}
                      </Badge>
                    ) : null}
                    <Badge variant={v.submission_tier === 'cve_candidate' ? 'info' : 'outline'}>{tier}</Badge>
                    <span className="text-xs text-slate-400">
                      #{v.id} · {projectName} · {v.vuln_type} · {formatSeverity(v.severity)}
                      {surface ? ` · ${surface}` : ''} · {formatDateTime(v.created_at)}
                    </span>
                  </div>
                </Link>
              </div>
            )
          })}
          {filtered.length === 0 ? <div className="p-4 text-sm text-muted-foreground">暂无数据</div> : null}
        </Card>

        {showDetailPane ? (
        <Card className="min-w-0 max-h-[calc(100vh-13rem)] overflow-auto">
          <CardContent className="p-5">
          {detail ? (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold">{detail.title}</h2>
              <div className="text-xs text-slate-400">
                {detailProject} · 产出时间 {formatDateTime(detail.created_at)}
              </div>
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
                {detail.evidence_level ? <Badge variant="outline">{detail.evidence_level}</Badge> : null}
                {detailSurface ? <Badge variant="info">{detailSurface}</Badge> : null}
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
            <div className="text-sm text-muted-foreground">选择左侧漏洞查看详情</div>
          )}
          </CardContent>
        </Card>
        ) : null}
      </div>
    </div>
  )
}
