import { useEffect, useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type PhaseReport, type PhaseReportDetail, type PhaseReportList } from '../api'
import { formatDateTime } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

const PHASES = [
  ['recon', '侦察'],
  ['worker', '挖掘'],
  ['reviewer', '审核'],
  ['verifier', '验证'],
  ['attack_chain', '攻击链'],
] as const

const SUB_TABS: Record<string, readonly [string, string][]> = {
  recon: [
    ['all', '全部'],
    ['map', '地图/鉴权'],
    ['source_ext', '扩展名'],
    ['old_vulns', '历史漏洞'],
    ['mark', '盖章'],
  ],
  worker: [
    ['all', '全部'],
    ['mine', '启发式'],
    ['fast', '快速扫描'],
    ['bypass', '历史漏洞绕过'],
    ['unconstrained', '无约束扫描'],
    ['fix', '修复'],
  ],
  reviewer: [
    ['all', '全部'],
    ['lab', '环境搭建'],
    ['reviewer', '审核'],
  ],
  verifier: [
    ['all', '全部'],
    ['verify', '互联网验证'],
  ],
  attack_chain: [
    ['all', '全部'],
    ['chain', '攻击链串联'],
  ],
}

const KIND_VARIANT: Record<string, 'info' | 'success' | 'warning' | 'outline'> = {
  doc: 'info',
  round: 'success',
  summary: 'outline',
  rescue: 'warning',
}
const PAGE_SIZE = 10

const EMPTY_REPORT_LIST: PhaseReportList = {
  phases: [],
  count: 0,
  selected_count: 0,
  limit: PAGE_SIZE,
  offset: 0,
  phase: '',
  subphase: '',
}

function roundHint(r: { kind: string; round: number | null }): string {
  if (r.round == null) return ''
  if (r.kind === 'round') return ` · 第 ${r.round} 轮`
  return ` · 第 ${r.round} 次`
}

function reportsOf(groups: { phase: string; reports: PhaseReport[] }[], phase: string): PhaseReport[] {
  return groups.find((g) => g.phase === phase)?.reports ?? []
}

export default function PhaseReportsPanel({
  projectId,
  initialPhase = 'worker',
}: {
  projectId: number
  initialPhase?: string
}) {
  const [phase, setPhase] = useState(
    initialPhase === 'reviewer'
      ? 'reviewer'
      : initialPhase === 'recon'
        ? 'recon'
        : initialPhase === 'verifier'
          ? 'verifier'
          : initialPhase === 'attack_chain'
            ? 'attack_chain'
            : 'worker',
  )
  const [sub, setSub] = useState('all')
  const [reportList, setReportList] = useState<PhaseReportList>(EMPTY_REPORT_LIST)
  const [visibleLimit, setVisibleLimit] = useState(PAGE_SIZE)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<PhaseReportDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  const groups = reportList.phases
  const all = useMemo(() => reportsOf(groups, phase), [groups, phase])
  const filtered = useMemo(
    () => (sub === 'all' ? all : all.filter((r) => r.subphase === sub)),
    [all, sub],
  )

  useEffect(() => {
    setSub('all')
  }, [phase])

  useEffect(() => {
    setVisibleLimit(PAGE_SIZE)
    setSelectedId(null)
    setDetail(null)
    setError(null)
  }, [projectId, phase, sub])

  useEffect(() => {
    let alive = true
    const subphase = sub === 'all' ? undefined : sub
    const load = () => {
      return api
        .listPhaseReports(projectId, { phase, subphase, limit: visibleLimit, offset: 0 })
        .then((d) => {
          if (!alive) return
          setReportList(d)
        })
        .catch(() => undefined)
    }
    const stop = startVisibilityPoll(load, 5000)
    return () => {
      alive = false
      stop()
    }
  }, [projectId, phase, sub, visibleLimit])

  // Keep selection only if still in the filtered list; do not auto-fetch first report.
  useEffect(() => {
    if (!filtered.length) {
      setSelectedId(null)
      setDetail(null)
      return
    }
    if (selectedId && !filtered.some((r) => r.id === selectedId)) {
      setSelectedId(null)
      setDetail(null)
    }
  }, [filtered, selectedId])

  useEffect(() => {
    if (!selectedId) {
      setDetail(null)
      return
    }
    let alive = true
    setError(null)
    api
      .getPhaseReport(projectId, selectedId)
      .then((d) => {
        if (alive) setDetail(d)
      })
      .catch((e) => {
        if (!alive) return
        setDetail(null)
        setError(e instanceof Error ? e.message : '读取失败')
      })
    return () => {
      alive = false
    }
  }, [projectId, selectedId])

  const counts = Object.fromEntries(groups.map((g) => [g.phase, g.count]))
  const subTabs = SUB_TABS[phase]
  const activeListMatches =
    reportList.phase === phase && reportList.subphase === (sub === 'all' ? '' : sub)
  const selectedTotal = activeListMatches ? reportList.selected_count : filtered.length
  const canLoadMore = filtered.length < selectedTotal

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {PHASES.map(([k, label]) => (
          <Button key={k} variant={phase === k ? 'default' : 'outline'} onClick={() => setPhase(k)}>
            {label}
            {counts[k] ? ` ${counts[k]}` : ''}
          </Button>
        ))}
      </div>
      {subTabs ? (
        <div className="flex flex-wrap gap-2">
          {subTabs.map(([k, label]) => (
            <Button key={k} variant={sub === k ? 'default' : 'outline'} onClick={() => setSub(k)}>
              {label}
            </Button>
          ))}
        </div>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-[minmax(260px,340px)_1fr]">
        <Card className="max-h-[calc(100vh-16rem)] gap-0 divide-y divide-border overflow-auto py-0">
          {filtered.map((r) => (
            <Button
              key={r.id}
              type="button"
              variant="ghost"
              onClick={() => setSelectedId(r.id)}
              className={`h-auto w-full justify-start rounded-none px-4 py-3 text-left hover:bg-muted ${
                selectedId === r.id ? 'bg-muted' : ''
              }`}
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate font-medium">{r.title}</div>
                  <Badge variant={KIND_VARIANT[r.kind] || 'outline'}>{r.kind_label}</Badge>
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  {r.subphase_label}
                  {roundHint(r)}
                  {` · ${formatDateTime(r.mtime)}`}
                </div>
                {r.preview ? <div className="mt-1 line-clamp-2 text-xs text-muted-foreground/70">{r.preview}</div> : null}
              </div>
            </Button>
          ))}
          {filtered.length === 0 ? <div className="p-4 text-sm text-muted-foreground">暂无该筛选报告</div> : null}
          {selectedTotal > 0 ? (
            <div className="space-y-2 p-3 text-center text-xs text-muted-foreground">
              <div>
                已显示最近 {filtered.length} / 共 {selectedTotal} 份报告
              </div>
              {canLoadMore ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="w-full"
                  onClick={() => setVisibleLimit((n) => n + PAGE_SIZE)}
                >
                  加载更早 10 份
                </Button>
              ) : null}
            </div>
          ) : null}
        </Card>
        <Card className="min-w-0 max-h-[calc(100vh-16rem)] overflow-auto">
          <CardContent className="p-5">
          {error ? <div className="text-sm text-red-300">{error}</div> : null}
          {detail ? (
            <div className="space-y-3">
              <div>
                <h2 className="text-lg font-semibold">{detail.title}</h2>
                <div className="mt-1 text-xs text-slate-400">
                  {detail.phase_label} · {detail.subphase_label} · {detail.kind_label}
                  {roundHint(detail)}
                  {` · ${formatDateTime(detail.mtime)}`}
                </div>
              </div>
              <div className="vh-md">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{detail.content || '_空报告_'}</ReactMarkdown>
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">{error ? '' : '选择左侧报告查看正文'}</div>
          )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
