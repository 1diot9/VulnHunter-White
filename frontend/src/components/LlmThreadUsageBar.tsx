import { useEffect, useState } from 'react'
import { CpuIcon } from 'lucide-react'
import { api, type LlmEndpointUsage, type LlmThreadUsage } from '../api'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

const EMPTY: LlmThreadUsage = { used: 0, limit: 6, waiting: 0, endpoints: [] }

const ERROR_KIND_KEY: Record<string, string> = {
  rate_limit: 'llm.error.rate_limit',
  quota: 'llm.error.quota',
  auth: 'llm.error.auth',
  transient: 'llm.error.transient',
}

export function errorKindLabel(kind?: string): string {
  const key = (kind || '').trim()
  const msgKey = key ? ERROR_KIND_KEY[key] : ''
  return msgKey ? t(msgKey) : ''
}

export function endpointSkipLabel(
  ep: Pick<LlmEndpointUsage, 'disabled' | 'cooldown_sec' | 'error_kind'>,
): string {
  if (ep.disabled) return t('llm.disabled')
  if (ep.cooldown_sec > 0) return t('llm.cooldown', { time: formatCooldownSec(ep.cooldown_sec) })
  return ''
}


export function formatCooldownSec(sec: number): string {
  const s = Math.max(0, Math.ceil(sec))
  if (s >= 3600) {
    const h = Math.floor(s / 3600)
    const m = Math.floor((s % 3600) / 60)
    return m ? `${h}h${m}m` : `${h}h`
  }
  if (s >= 90) {
    const m = Math.floor(s / 60)
    const r = s % 60
    return r ? `${m}m${r}s` : `${m}m`
  }
  return `${s}s`
}

export function endpointCooldownReason(ep: Pick<LlmEndpointUsage, 'error_kind' | 'last_error'>): string {
  const kind = errorKindLabel(ep.error_kind)
  const detail = (ep.last_error || '').trim()
  if (kind && detail && detail !== ep.error_kind) return t('llm.reasonWithDetail', { kind, detail })
  return detail || kind
}

function clampPct(used: number, limit: number): number {
  if (limit <= 0) return 0
  return Math.max(0, Math.min(100, (used / limit) * 100))
}

function shortUrl(url: string): string {
  const raw = (url || '').replace(/^https?:\/\//, '')
  return raw.length > 36 ? `${raw.slice(0, 34)}…` : raw || t('llm.unconfigured')
}

export default function LlmThreadUsageBar({ className }: { className?: string }) {
  const { t: tt } = useI18n()
  const [usage, setUsage] = useState<LlmThreadUsage>(EMPTY)

  useEffect(
    () =>
      startVisibilityPoll(() => {
        return api
          .llmThreadUsage()
          .then(setUsage)
          .catch(() => {})
      }, 2000),
    [],
  )

  const { used, limit, waiting, endpoints = [] } = usage
  const pct = clampPct(used, limit)
  const full = used >= limit
  const barClass = full
    ? 'bg-amber-400'
    : used > 0
      ? 'bg-sky-400'
      : 'bg-muted-foreground/40'

  return (
    <TooltipProvider delay={200}>
      <Tooltip>
        <TooltipTrigger
          render={
            <div
              className={cn(
                'min-w-52 cursor-default rounded-xl bg-card px-3 py-2 ring-1 ring-foreground/10',
                className,
              )}
            />
          }
        >
          <div className="flex items-center justify-between gap-3 text-xs">
            <span className="inline-flex items-center gap-1.5 font-medium text-foreground">
              <CpuIcon className="size-3.5 text-muted-foreground" />
              {tt('llm.thread')}
            </span>
            <span className={cn('tabular-nums', full ? 'text-amber-200' : 'text-muted-foreground')}>
              {used} / {limit}
              {waiting > 0 ? (
                <span className="ml-1.5 text-amber-200">{tt('llm.waiting', { n: waiting })}</span>
              ) : null}
            </span>
          </div>
          <div
            className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted"
            role="progressbar"
            aria-label={tt('llm.threadAria')}
            aria-valuemin={0}
            aria-valuemax={limit}
            aria-valuenow={used}
          >
            <div
              className={cn('h-full rounded-full transition-[width] duration-300', barClass)}
              style={{ width: `${pct}%` }}
            />
          </div>
        </TooltipTrigger>
        <TooltipContent side="bottom" className="max-w-md text-left leading-relaxed whitespace-normal">
          <p>{tt('llm.tooltip')}</p>
          {endpoints.length > 0 ? (
            <ul className="mt-2 space-y-1.5 border-t border-background/20 pt-2 text-[11px]">
              {endpoints.map((ep) => {
                const reason = endpointCooldownReason(ep)
                const skip = endpointSkipLabel(ep)
                return (
                  <li key={ep.id} className="tabular-nums">
                    <span className="font-medium">{ep.id}</span>
                    <span className="opacity-70"> · {shortUrl(ep.base_url)}</span>
                    <span className="ml-1">
                      {ep.used}/{ep.limit}
                    </span>
                    {skip ? <span className="ml-1 font-medium">{skip}</span> : null}
                    {skip && reason ? (
                      <span className="mt-0.5 block break-all whitespace-pre-wrap opacity-80">{reason}</span>
                    ) : null}
                  </li>
                )
              })}
            </ul>
          ) : null}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
