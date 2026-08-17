import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRightIcon } from 'lucide-react'
import type { Vuln } from '../api'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { groupVulnsByRootCause } from '../lib/vulnGroups'
import {
  cn,
  formatAttackSurface,
  formatDateTime,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
  severityScoreBadgeClass,
} from '../lib/utils'

const STATUS_LABEL: Record<string, string> = {
  pending_review: '待审',
  confirmed: '已确认',
  false_positive: '误报',
  static_only: '仅静态',
  returned: '已打回',
}

function StatusBadges({ v }: { v: Vuln }) {
  const surface = formatAttackSurface(v.attack_surface, v.required_account)
  const score = formatSeverityScore(v.severity_score)
  const tier = formatSubmissionTier(v.submission_tier)
  return (
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
      {surface ? <span className="text-xs text-slate-400">{surface}</span> : null}
    </div>
  )
}

function VulnRow({
  v,
  active,
  nested,
  projectName,
  selected,
  onToggleSelect,
}: {
  v: Vuln
  active: boolean
  nested?: boolean
  projectName: string
  selected?: boolean
  onToggleSelect?: (id: number, checked: boolean) => void
}) {
  return (
    <div className={cn('flex items-start gap-2 px-2.5 py-2.5', active && 'bg-muted', nested && 'bg-muted/30')}>
      {onToggleSelect ? (
        <Checkbox
          className="mt-1 shrink-0"
          checked={Boolean(selected)}
          onCheckedChange={(checked) => onToggleSelect(v.id, checked === true)}
        />
      ) : null}
      <Link to={`/vulns/${v.id}`} className="min-w-0 flex-1 hover:underline">
        <div className={cn('break-words font-medium leading-snug', nested && 'text-sm')}>{v.title}</div>
        <StatusBadges v={v} />
        <div className="mt-1 text-xs text-slate-400">
          #{v.id} · {projectName} · {v.vuln_type} · {formatSeverity(v.severity)}
          {v.file_path ? ` · ${v.file_path}${v.line_no != null ? `:${v.line_no}` : ''}` : ''} · {formatDateTime(v.created_at)}
        </div>
      </Link>
    </div>
  )
}

export default function VulnGroupList({
  vulns,
  activeId,
  selectedIds,
  onToggleSelect,
  projectNameById,
  emptyText = '暂无数据',
}: {
  vulns: Vuln[]
  activeId?: number | null
  selectedIds?: number[]
  onToggleSelect?: (id: number, checked: boolean) => void
  projectNameById?: Map<number, string>
  emptyText?: string
}) {
  const groups = useMemo(() => groupVulnsByRootCause(vulns), [vulns])
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())

  useEffect(() => {
    if (activeId == null) return
    const hit = groups.find((g) => g.others.some((v) => v.id === activeId))
    if (!hit) return
    setExpanded((prev) => {
      if (prev.has(hit.id)) return prev
      const next = new Set(prev)
      next.add(hit.id)
      return next
    })
  }, [activeId, groups])

  const selectedSet = useMemo(() => new Set(selectedIds ?? []), [selectedIds])

  if (groups.length === 0) {
    return <div className="p-4 text-sm text-muted-foreground">{emptyText}</div>
  }

  return (
    <>
      {groups.map((group) => {
        const open = expanded.has(group.id)
        const projectName =
          group.primary.project_name ||
          projectNameById?.get(group.primary.project_id) ||
          `项目 ${group.primary.project_id}`
        const hasOthers = group.others.length > 0
        return (
          <div key={group.id}>
            <div className="flex items-start">
              <div className="flex w-7 shrink-0 justify-center pt-2.5">
                {hasOthers ? (
                  <button
                    type="button"
                    className="rounded p-0.5 text-slate-400 hover:bg-muted hover:text-slate-200"
                    aria-expanded={open}
                    aria-label={open ? '收起同根因报告' : `展开 ${group.others.length} 条同根因报告`}
                    onClick={() =>
                      setExpanded((prev) => {
                        const next = new Set(prev)
                        if (next.has(group.id)) next.delete(group.id)
                        else next.add(group.id)
                        return next
                      })
                    }
                  >
                    <ChevronRightIcon className={cn('size-4 transition-transform', open && 'rotate-90')} />
                  </button>
                ) : null}
              </div>
              <div className="min-w-0 flex-1">
                <VulnRow
                  v={group.primary}
                  active={activeId === group.primary.id}
                  projectName={projectName}
                  selected={selectedSet.has(group.primary.id)}
                  onToggleSelect={onToggleSelect}
                />
                {hasOthers ? (
                  <button
                    type="button"
                    className="mb-2 ml-2.5 text-xs text-slate-400 hover:text-slate-200"
                    onClick={() =>
                      setExpanded((prev) => {
                        const next = new Set(prev)
                        if (next.has(group.id)) next.delete(group.id)
                        else next.add(group.id)
                        return next
                      })
                    }
                  >
                    {open ? '收起' : `还有 ${group.others.length} 条同根因`}
                    {group.rootCauseKey ? ` · ${group.rootCauseKey}` : ''}
                  </button>
                ) : null}
              </div>
            </div>
            {open
              ? group.others.map((v) => (
                  <div key={v.id} className="border-t border-border/50 pl-7">
                    <VulnRow
                      v={v}
                      active={activeId === v.id}
                      nested
                      projectName={v.project_name || projectNameById?.get(v.project_id) || projectName}
                      selected={selectedSet.has(v.id)}
                      onToggleSelect={onToggleSelect}
                    />
                  </div>
                ))
              : null}
          </div>
        )
      })}
    </>
  )
}
