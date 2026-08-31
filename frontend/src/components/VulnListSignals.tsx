import { Fragment } from 'react'
import { EllipsisIcon } from 'lucide-react'
import type { Vuln } from '../api'
import { vulnListAttributeLines, vulnListSecondaryTags } from '../lib/vulnListTags'
import AttackSurfaceBadge from './AttackSurfaceBadge'
import ExposureModeBadge from './ExposureModeBadge'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  cn,
  formatSeverityScore,
  formatVulnType,
  formatVulnStatus,
  harnessTierTooltip,
  severityScoreBadgeClass,
} from '@/lib/utils'

function InlineTag({ label, tooltip }: { label: string; tooltip?: string | null }) {
  const text = (
    <span className={cn('cursor-default underline decoration-slate-600/60 decoration-dotted underline-offset-2')}>
      {label}
    </span>
  )
  if (!tooltip) return text
  return (
    <Tooltip>
      <TooltipTrigger render={<span className="inline cursor-help" />}>{text}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-sm text-left leading-relaxed whitespace-pre-line">
        {tooltip}
      </TooltipContent>
    </Tooltip>
  )
}

function AllAttributesTip({ v, projectName }: { v: Vuln; projectName?: string }) {
  const lines = vulnListAttributeLines(v, projectName)
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            type="button"
            className="inline-flex size-4 shrink-0 items-center justify-center rounded text-slate-500 hover:bg-muted hover:text-slate-300"
            aria-label="查看全部属性"
          />
        }
      >
        <EllipsisIcon className="size-3" />
      </TooltipTrigger>
      <TooltipContent side="bottom" align="start" className="max-w-md p-0">
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 px-3 py-2.5 text-left text-[11px] leading-snug">
          {lines.map((row) => (
            <Fragment key={row.label}>
              <dt className="text-muted-foreground">{row.label}</dt>
              <dd className="min-w-0 break-words text-popover-foreground">{row.value}</dd>
            </Fragment>
          ))}
        </dl>
      </TooltipContent>
    </Tooltip>
  )
}

export default function VulnListSignals({
  v,
  nested,
  projectName,
}: {
  v: Vuln
  nested?: boolean
  projectName?: string
}) {
  const score = formatSeverityScore(v.severity_score, v.severity, v.cvss_vector)
  const vulnType = formatVulnType(v.vuln_type)
  const secondary = vulnListSecondaryTags(v, nested)

  const statusVariant =
    v.status === 'confirmed' || v.status === 'static_only'
      ? 'success'
      : v.status === 'false_positive'
        ? 'destructive'
        : nested
          ? 'outline'
          : 'warning'

  const compact = nested ? 'h-4 px-1.5 text-[10px]' : undefined

  return (
    <div className={cn('mt-1 space-y-0.5', nested && 'mt-0.5')}>
      <div className={cn('flex flex-wrap items-center gap-1.5', nested && 'gap-1')}>
        <Tooltip>
          <TooltipTrigger render={<span className="inline" />}>
            <Badge className={compact} variant={statusVariant}>
              {formatVulnStatus(v.status, v.evidence_level, v.fp_kind, v.harness_depth)}
            </Badge>
          </TooltipTrigger>
          {harnessTierTooltip(v.evidence_level, v.harness_depth) ? (
            <TooltipContent side="top" className="max-w-xs">
              {harnessTierTooltip(v.evidence_level, v.harness_depth)}
            </TooltipContent>
          ) : null}
        </Tooltip>
        {vulnType ? (
          <Badge className={compact} variant="outline">
            {vulnType}
          </Badge>
        ) : null}
        {score ? (
          <Badge
            variant="outline"
            className={cn(severityScoreBadgeClass(v.severity_score, v.cvss_vector), compact)}
            title={v.cvss_vector || undefined}
          >
            {score}
          </Badge>
        ) : null}
        <AttackSurfaceBadge
          attackSurface={v.attack_surface}
          requiredAccount={v.required_account}
          nested={nested}
        />
        <ExposureModeBadge
          exposureMode={v.exposure_mode}
          upstreamChainProven={v.upstream_chain_proven}
          nested={nested}
        />
      </div>
      {secondary.length > 0 ? (
        <div
          className={cn(
            'flex flex-wrap items-center gap-x-1 text-[11px] leading-4 text-slate-500',
            nested && 'text-[10px] text-slate-600',
          )}
        >
          {secondary.map((tag, index) => (
            <span key={`${tag.label}-${index}`} className="inline-flex items-center gap-x-1">
              {index > 0 ? <span aria-hidden className="text-slate-600">·</span> : null}
              <InlineTag label={tag.label} tooltip={tag.tooltip} />
            </span>
          ))}
          <span aria-hidden className="text-slate-600">·</span>
          <AllAttributesTip v={v} projectName={projectName} />
        </div>
      ) : (
        <div className={cn('flex items-center', nested && 'text-[10px]')}>
          <AllAttributesTip v={v} projectName={projectName} />
        </div>
      )}
    </div>
  )
}
