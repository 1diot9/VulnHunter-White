import { useEffect, useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, formatApiError, type PhaseReport, type PhaseReportDetail, type PhaseReportList } from '../api'
import { formatDateTime } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { Badge } from '@/components/ui/badge'
import { useI18n } from '@/i18n'
import type { MessageVars } from '@/i18n/t'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'

type Translate = (key: string, vars?: MessageVars) => string

function reportPhases(t: Translate) {
  return [
    ['recon', t('flow.reports.recon')],
    ['worker', t('flow.reports.worker')],
    ['reviewer', t('flow.reports.reviewer')],
    ['verifier', t('flow.reports.verifier')],
    ['attack_chain', t('flow.reports.attackChain')],
    ['vuln_dedup', t('flow.reports.dedup')],
  ] as const
}

function reportSubTabs(t: Translate): Record<string, readonly [string, string][]> {
  return {
    recon: [
      ['all', t('flow.reports.all')],
      ['map', t('flow.reports.map')],
      ['source_ext', t('flow.reports.ext')],
      ['old_vulns', t('flow.reports.oldVulns')],
      ['mark', t('flow.reports.mark')],
    ],
    worker: [
      ['all', t('flow.reports.all')],
      ['mine', t('flow.reports.mine')],
      ['fast', t('mining.fast')],
      ['bypass', t('mining.bypass')],
      ['unconstrained', t('mining.unconstrained')],
      ['fix', t('flow.reports.fix')],
    ],
    reviewer: [
      ['all', t('flow.reports.all')],
      ['lab', t('flow.reports.lab')],
      ['reviewer', t('flow.reports.reviewer')],
    ],
    verifier: [
      ['all', t('flow.reports.all')],
      ['verify', t('flow.reports.internet')],
    ],
    attack_chain: [
      ['all', t('flow.reports.all')],
      ['chain', t('flow.reports.chain')],
    ],
    vuln_dedup: [
      ['all', t('flow.reports.all')],
      ['dedup', t('flow.reports.dedupVulns')],
    ],
  }
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

function roundHint(r: { kind: string; round: number | null }, t: Translate): string {
  if (r.round == null) return ''
  if (r.kind === 'round') return t('flow.reports.round', { n: r.round })
  return t('flow.reports.times', { n: r.round })
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
  const { t } = useI18n()
  const PHASES = reportPhases(t)
  const SUB_TABS = reportSubTabs(t)
  const [phase, setPhase] = useState(
    initialPhase === 'reviewer'
      ? 'reviewer'
      : initialPhase === 'recon'
        ? 'recon'
        : initialPhase === 'verifier'
          ? 'verifier'
          : initialPhase === 'attack_chain'
            ? 'attack_chain'
            : initialPhase === 'vuln_dedup'
              ? 'vuln_dedup'
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
        setError(formatApiError(e, t('flow.reports.loadTimeout')))
      })
    return () => {
      alive = false
    }
  }, [projectId, selectedId, t])

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
                  {roundHint(r, t)}
                  {` · ${formatDateTime(r.mtime)}`}
                </div>
                {r.preview ? <div className="mt-1 line-clamp-2 text-xs text-muted-foreground/70">{r.preview}</div> : null}
              </div>
            </Button>
          ))}
          {filtered.length === 0 ? <div className="p-4 text-sm text-muted-foreground">{t('flow.reports.emptyFilter')}</div> : null}
          {selectedTotal > 0 ? (
            <div className="space-y-2 p-3 text-center text-xs text-muted-foreground">
              <div>
                {t('flow.reports.shown', { shown: filtered.length, total: selectedTotal })}
              </div>
              {canLoadMore ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="w-full"
                  onClick={() => setVisibleLimit((n) => n + PAGE_SIZE)}
                >
                  {t('flow.reports.loadMoreShort')}
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
                  {roundHint(detail, t)}
                  {` · ${formatDateTime(detail.mtime)}`}
                </div>
              </div>
              <div className="vh-md">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{detail.content || t('flow.reports.emptyMdGfm')}</ReactMarkdown>
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">{error ? '' : t('flow.reports.pickHint')}</div>
          )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
