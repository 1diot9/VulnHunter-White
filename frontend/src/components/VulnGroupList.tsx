import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRightIcon, DownloadIcon } from 'lucide-react'
import { api, type Vuln } from '../api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { TooltipProvider } from '@/components/ui/tooltip'
import VulnListSignals from './VulnListSignals'
import { filterVulnGroups, groupVulnsByRootCause, type VulnTierFilter } from '../lib/vulnGroups'
import {
  cn,
  formatDateTime,
  formatVulnProjectName,
  saveBlob,
} from '../lib/utils'

async function downloadReport(id: number) {
  try {
    const { blob, filename } = await api.downloadVulnReport(id)
    saveBlob(blob, filename)
  } catch {
    /* ignore transient */
  }
}

function VulnRow({
  v,
  active,
  nested,
  projectName,
  projectKind,
  selected,
  onToggleSelect,
  onSelectVuln,
}: {
  v: Vuln
  active: boolean
  nested?: boolean
  projectName: string
  projectKind?: string | null
  selected?: boolean
  onToggleSelect?: (id: number, checked: boolean) => void
  onSelectVuln?: (id: number) => void
}) {
  const titleBlock = (
    <>
      <div
        className={cn(
          'break-words leading-snug',
          nested ? 'text-[11px] font-normal leading-4 text-slate-400' : 'font-medium',
        )}
      >
        {v.title}
      </div>
      <VulnListSignals v={v} nested={nested} projectName={projectName} />
      {v.verifier_status === 'verified' && v.verifier_verified_url ? (
        <div
          className={cn(
            'mt-1 break-all text-xs text-emerald-300/90',
            nested && 'mt-0.5 text-[10px] text-emerald-400/70',
          )}
        >
          复现目标 {v.verifier_verified_url}
        </div>
      ) : null}
      <div className={cn('mt-1 text-xs text-slate-400', nested && 'mt-0.5 text-[10px] text-slate-600')}>
        #{v.id} · {formatVulnProjectName(projectName, projectKind ?? v.project_target_kind)}
        {v.file_path ? ` · ${v.file_path}${v.line_no != null ? `:${v.line_no}` : ''}` : ''} · {formatDateTime(v.created_at)}
      </div>
    </>
  )

  return (
    <div
      className={cn(
        'flex items-start gap-2',
        nested
          ? cn(
              'rounded-r-md border-l-[3px] border-cyan-700 bg-slate-950/80 px-2 py-1 text-slate-500',
              active && 'border-cyan-400 bg-cyan-950/40 text-slate-300',
              v.tracking_status === 'submitted' && 'border-emerald-600/80 bg-emerald-500/20 text-slate-300',
            )
          : cn(
              'px-2.5 py-2.5',
              active && v.tracking_status !== 'submitted' && 'bg-muted',
              v.tracking_status === 'submitted' && 'bg-emerald-500/20',
              v.tracking_status === 'ignored' && 'opacity-60',
            ),
      )}
    >
      {onToggleSelect ? (
        <Checkbox
          className={cn('mt-1 shrink-0', nested && 'mt-0.5')}
          checked={Boolean(selected)}
          onCheckedChange={(checked) => onToggleSelect(v.id, checked === true)}
        />
      ) : null}
      {onSelectVuln ? (
        <button
          type="button"
          className="min-w-0 flex-1 cursor-pointer text-left hover:underline"
          onClick={() => onSelectVuln(v.id)}
        >
          {titleBlock}
        </button>
      ) : (
        <Link to={`/vulns/${v.id}`} className="min-w-0 flex-1 hover:underline">
          {titleBlock}
        </Link>
      )}
      <Button
        type="button"
        variant="ghost"
        size={nested ? 'icon-xs' : 'icon-sm'}
        className="mt-0.5 shrink-0 text-slate-400 hover:text-slate-100"
        aria-label={`下载 #${v.id} 报告与 PoC`}
        onClick={() => {
          void downloadReport(v.id)
        }}
      >
        <DownloadIcon />
      </Button>
    </div>
  )
}

export default function VulnGroupList({
  vulns,
  activeId,
  selectedIds,
  onToggleSelect,
  onSelectVuln,
  projectNameById,
  projectKindById,
  tierFilter = 'all',
  emptyText = '暂无数据',
  expandAll = false,
}: {
  vulns: Vuln[]
  activeId?: number | null
  selectedIds?: number[]
  onToggleSelect?: (id: number, checked: boolean) => void
  onSelectVuln?: (id: number) => void
  projectNameById?: Map<number, string>
  projectKindById?: Map<number, string>
  tierFilter?: VulnTierFilter
  emptyText?: string
  expandAll?: boolean
}) {
  const groups = useMemo(
    () => filterVulnGroups(groupVulnsByRootCause(vulns), tierFilter),
    [vulns, tierFilter],
  )
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())

  useEffect(() => {
    if (!expandAll) return
    setExpanded(new Set(groups.filter((g) => g.others.length > 0).map((g) => g.id)))
  }, [expandAll, groups])

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
    <TooltipProvider delay={200}>
      {groups.map((group) => {
        const open = expanded.has(group.id)
        const projectName =
          group.primary.project_name ||
          projectNameById?.get(group.primary.project_id) ||
          `项目 ${group.primary.project_id}`
        const hasOthers = group.others.length > 0
        return (
          <div key={group.id}>
          <div
            className={cn(
              'flex items-start',
              group.primary.tracking_status === 'submitted' && 'bg-emerald-500/20',
            )}
          >
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
                  projectKind={projectKindById?.get(group.primary.project_id)}
                  selected={selectedSet.has(group.primary.id)}
                  onToggleSelect={onToggleSelect}
                  onSelectVuln={onSelectVuln}
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
                    {open ? '收起同根因子项' : `还有 ${group.others.length} 条同根因`}
                    {group.rootCauseKey ? ` · ${group.rootCauseKey}` : ''}
                  </button>
                ) : null}
              </div>
            </div>
            {open ? (
              <div className="space-y-1 bg-slate-950/40 py-1.5 pr-2 pl-7">
                {group.others.map((v) => (
                  <VulnRow
                    key={v.id}
                    v={v}
                    active={activeId === v.id}
                    nested
                    projectName={v.project_name || projectNameById?.get(v.project_id) || projectName}
                    projectKind={projectKindById?.get(v.project_id)}
                    selected={selectedSet.has(v.id)}
                    onToggleSelect={onToggleSelect}
                    onSelectVuln={onSelectVuln}
                  />
                ))}
              </div>
            ) : null}
          </div>
        )
      })}
    </TooltipProvider>
  )
}
