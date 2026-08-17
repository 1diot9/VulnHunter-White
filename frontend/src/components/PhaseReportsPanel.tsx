import { useEffect, useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type PhaseReport, type PhaseReportDetail } from '../api'
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
    ['mine', '挖掘'],
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
}

const KIND_VARIANT: Record<string, 'info' | 'success' | 'warning' | 'outline'> = {
  doc: 'info',
  round: 'success',
  summary: 'outline',
  rescue: 'warning',
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
          : 'worker',
  )
  const [sub, setSub] = useState('all')
  const [groups, setGroups] = useState<{ phase: string; label: string; count: number; reports: PhaseReport[] }[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<PhaseReportDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  const all = useMemo(() => reportsOf(groups, phase), [groups, phase])
  const filtered = useMemo(
    () => (sub === 'all' ? all : all.filter((r) => r.subphase === sub)),
    [all, sub],
  )

  useEffect(() => {
    setSub('all')
  }, [phase])

  useEffect(() => {
    let alive = true
    const load = () => {
      api
        .listPhaseReports(projectId)
        .then((d) => {
          if (!alive) return
          setGroups(d.phases)
        })
        .catch(() => undefined)
    }
    const stop = startVisibilityPoll(load, 5000)
    return () => {
      alive = false
      stop()
    }
  }, [projectId])

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
          {filtered.length === 0 ? <div className="p-4 text-sm text-muted-foreground">暂无该阶段报告</div> : null}
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
