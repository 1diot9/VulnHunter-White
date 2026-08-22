import { useEffect, useState } from 'react'
import { CpuIcon } from 'lucide-react'
import { api, type LlmThreadUsage } from '../api'
import { cn } from '@/lib/utils'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const EMPTY: LlmThreadUsage = { used: 0, limit: 6, waiting: 0 }

function clampPct(used: number, limit: number): number {
  if (limit <= 0) return 0
  return Math.max(0, Math.min(100, (used / limit) * 100))
}

export default function LlmThreadUsageBar({ className }: { className?: string }) {
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

  const { used, limit, waiting } = usage
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
              LLM 线程
            </span>
            <span className={cn('tabular-nums', full ? 'text-amber-200' : 'text-muted-foreground')}>
              {used} / {limit}
              {waiting > 0 ? <span className="ml-1.5 text-amber-200">排队 {waiting}</span> : null}
            </span>
          </div>
          <div
            className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted"
            role="progressbar"
            aria-label="LLM 线程占用"
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
        <TooltipContent side="bottom" className="max-w-xs text-left leading-relaxed whitespace-normal">
          所有运行中项目的侦察、挖掘、审核等 LLM 会话合计占用。超出上限的工作按到达顺序排队。可在设置页改总线程数。
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
