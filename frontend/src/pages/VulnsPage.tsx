import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, type Project, type Vuln, type VulnDetail } from '../api'
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
import VulnGroupList from '../components/VulnGroupList'
import { filterVulnGroups, groupVulnsByRootCause, type VulnTierFilter } from '../lib/vulnGroups'
import {
  formatAttackSurface,
  formatDateTime,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
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

export default function VulnsPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const detailId = id ? Number(id) : null
  const [filter, setFilter] = useState<'all' | 'confirmed' | 'false_positive' | 'pending_review'>('all')
  const [surfaceFilter, setSurfaceFilter] = useState<'all' | 'frontend' | 'backend'>('all')
  const [tierFilter, setTierFilter] = useState<VulnTierFilter>('all')
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
      )
      .then(setVulns)
      .catch(() => {})

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
  }, [])

  useEffect(() => startVisibilityPoll(refresh, 5000), [filter, projectId, surfaceFilter])

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

  const visibleVulns = useMemo(
    () => filterVulnGroups(groupVulnsByRootCause(vulns), tierFilter).flatMap((g) => [g.primary, ...g.others]),
    [vulns, tierFilter],
  )
  const cveCandidateIds = useMemo(
    () => vulns.filter((v) => v.submission_tier === 'cve_candidate').map((v) => v.id),
    [vulns],
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

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">漏洞产出</h1>
          <p className="text-sm text-slate-400">按项目、状态与价值分层筛选；同根因报告折叠在危害最大的条目下。</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={downloadCveCandidates} disabled={!cveCandidateIds.length && !selected.length}>
            仅下载有 CVE 价值
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
          vulns={vulns}
          tierFilter={tierFilter}
          activeId={detailId}
          selectedIds={selected}
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
                  {detail.evidence_level && detail.evidence_level !== 'static_only' ? (
                    <Badge variant="outline">{detail.evidence_level}</Badge>
                  ) : null}
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
