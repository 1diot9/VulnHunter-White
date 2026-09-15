import { useEffect, useMemo, useState } from 'react'
import { ChevronLeftIcon, ChevronRightIcon } from 'lucide-react'
import { api, type Vuln, type VulnCalendarDay } from '../api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import VulnGroupList from './VulnGroupList'
import { cn } from '../lib/utils'
import { useI18n } from '@/i18n'
import { startVisibilityPoll } from '../lib/visibilityPoll'


function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

function shanghaiYmd(d = new Date()): { year: number; month: number; date: string } {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(d)
  const year = Number(parts.find((p) => p.type === 'year')?.value)
  const month = Number(parts.find((p) => p.type === 'month')?.value)
  const day = Number(parts.find((p) => p.type === 'day')?.value)
  return { year, month, date: `${year}-${pad2(month)}-${pad2(day)}` }
}

function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate()
}

/** Monday = 0 … Sunday = 6 for a civil YYYY-MM-DD. */
function weekdayMon0(year: number, month: number, day: number): number {
  const wd = new Date(Date.UTC(year, month - 1, day, 12)).getUTCDay()
  return (wd + 6) % 7
}

function isCalendarOutcome(v: Vuln): boolean {
  return v.status === 'confirmed' || v.status === 'static_only' || v.status === 'false_positive'
}

function shiftMonth(year: number, month: number, delta: number): { year: number; month: number } {
  const idx = year * 12 + (month - 1) + delta
  return { year: Math.floor(idx / 12), month: (idx % 12) + 1 }
}

export default function VulnCalendar({
  projectId,
  projectNameById,
  projectKindById,
  onOpenVuln,
}: {
  projectId?: number
  projectNameById: Map<number, string>
  projectKindById?: Map<number, string>
  onOpenVuln?: (id: number) => void
}) {
  const { t } = useI18n()
  const WEEKDAYS = [t('comp.cal.wd0'), t('comp.cal.wd1'), t('comp.cal.wd2'), t('comp.cal.wd3'), t('comp.cal.wd4'), t('comp.cal.wd5'), t('comp.cal.wd6')]
  const today = useMemo(() => shanghaiYmd(), [])
  const [year, setYear] = useState(today.year)
  const [month, setMonth] = useState(today.month)
  const [days, setDays] = useState<VulnCalendarDay[]>([])
  const [selectedDate, setSelectedDate] = useState<string | null>(null)
  const [dayVulns, setDayVulns] = useState<Vuln[]>([])
  const [dayLoading, setDayLoading] = useState(false)

  const byDate = useMemo(() => {
    const map = new Map<string, VulnCalendarDay>()
    for (const d of days) map.set(d.date, d)
    return map
  }, [days])

  const monthTotal = useMemo(() => {
    let confirmed = 0
    let falsePositive = 0
    for (const d of days) {
      confirmed += d.confirmed
      falsePositive += d.false_positive
    }
    return { confirmed, falsePositive }
  }, [days])

  const cells = useMemo(() => {
    const total = daysInMonth(year, month)
    const lead = weekdayMon0(year, month, 1)
    const out: Array<{ date: string; day: number } | null> = []
    for (let i = 0; i < lead; i++) out.push(null)
    for (let day = 1; day <= total; day++) {
      out.push({ date: `${year}-${pad2(month)}-${pad2(day)}`, day })
    }
    while (out.length % 7 !== 0) out.push(null)
    return out
  }, [year, month])

  useEffect(() => {
    const refresh = () =>
      api
        .getVulnCalendar(year, month, projectId)
        .then((body) => setDays(body.days))
        .catch(() => {})
    return startVisibilityPoll(refresh, 30000)
  }, [year, month, projectId])

  useEffect(() => {
    if (!selectedDate) {
      setDayVulns([])
      return
    }
    let cancelled = false
    setDayLoading(true)
    api
      .listAllVulns({ projectId, createdDate: selectedDate })
      .then((rows) => {
        if (!cancelled) setDayVulns(rows.filter(isCalendarOutcome))
      })
      .catch(() => {
        if (!cancelled) setDayVulns([])
      })
      .finally(() => {
        if (!cancelled) setDayLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selectedDate, projectId])

  const selectedCounts = selectedDate ? byDate.get(selectedDate) : undefined
  const selectedLabel = selectedDate
    ? t('comp.cal.selected', { date: selectedDate, confirmed: selectedCounts?.confirmed ?? 0, fp: selectedCounts?.false_positive ?? 0 })
    : ''

  function goMonth(delta: number) {
    const next = shiftMonth(year, month, delta)
    setYear(next.year)
    setMonth(next.month)
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <CardTitle>{t('comp.cal.title')}</CardTitle>
            <CardDescription>
              {t('comp.cal.desc', { confirmed: monthTotal.confirmed, fp: monthTotal.falsePositive })}
              {projectId != null ? t('comp.cal.filtered') : ''}
            </CardDescription>
          </div>
          <div className="flex items-center gap-1">
            <Button type="button" variant="outline" size="icon-sm" aria-label={t('comp.cal.prev')} onClick={() => goMonth(-1)}>
              <ChevronLeftIcon className="size-4" />
            </Button>
            <div className="min-w-28 text-center text-sm font-medium tabular-nums">
              {t('comp.cal.month', { year, month })}
            </div>
            <Button type="button" variant="outline" size="icon-sm" aria-label={t('comp.cal.next')} onClick={() => goMonth(1)}>
              <ChevronRightIcon className="size-4" />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="ml-1"
              onClick={() => {
                setYear(today.year)
                setMonth(today.month)
              }}
            >
              {t('comp.cal.thisMonth')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-7 gap-1 text-center text-xs text-muted-foreground">
            {WEEKDAYS.map((label) => (
              <div key={label} className="py-1 font-medium">
                {label}
              </div>
            ))}
          </div>
          <div className="mt-1 grid grid-cols-7 gap-1">
            {cells.map((cell, idx) => {
              if (!cell) {
                return <div key={`empty-${idx}`} className="min-h-16 rounded-md bg-muted/20" />
              }
              const counts = byDate.get(cell.date)
              const confirmed = counts?.confirmed ?? 0
              const falsePositive = counts?.false_positive ?? 0
              const hasData = confirmed > 0 || falsePositive > 0
              const isToday = cell.date === today.date
              return (
                <button
                  key={cell.date}
                  type="button"
                  onClick={() => setSelectedDate(cell.date)}
                  className={cn(
                    'flex min-h-16 flex-col items-stretch rounded-md px-1.5 py-1.5 text-left transition-colors',
                    'ring-1 ring-foreground/10 hover:bg-muted/50',
                    isToday && 'ring-emerald-700/60',
                    hasData && 'bg-muted/30',
                  )}
                >
                  <span className={cn('text-xs tabular-nums', isToday ? 'font-semibold text-emerald-300' : 'text-slate-300')}>
                    {cell.day}
                  </span>
                  {hasData ? (
                    <div className="mt-auto space-y-0.5 pt-1 text-[10px] leading-tight">
                      {confirmed > 0 ? (
                        <div className="text-emerald-400/90">{t('comp.cal.confirmed', { n: confirmed })}</div>
                      ) : null}
                      {falsePositive > 0 ? (
                        <div className="text-red-300/90">{t('comp.cal.fp', { n: falsePositive })}</div>
                      ) : null}
                    </div>
                  ) : (
                    <div className="mt-auto pt-1 text-[10px] text-slate-600">—</div>
                  )}
                </button>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <Dialog open={selectedDate != null} onOpenChange={(open) => !open && setSelectedDate(null)}>
        <DialogContent className="flex max-h-[min(90vh,40rem)] w-full flex-col gap-3 sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('comp.cal.dialogTitle')}</DialogTitle>
            <DialogDescription>{selectedLabel}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto rounded-lg ring-1 ring-foreground/10">
            {dayLoading ? (
              <div className="px-3 py-6 text-sm text-muted-foreground">{t('comp.cal.loading')}</div>
            ) : (
              <VulnGroupList
                vulns={dayVulns}
                tierFilter="all"
                emptyText={t('comp.cal.empty')}
                projectNameById={projectNameById}
                projectKindById={projectKindById}
                onSelectVuln={(id) => {
                  onOpenVuln?.(id)
                  setSelectedDate(null)
                }}
              />
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
