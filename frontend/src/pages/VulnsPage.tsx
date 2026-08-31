import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ChevronLeftIcon, ChevronRightIcon, SearchIcon, XIcon } from 'lucide-react'
import { api, type ProjectName, type Vuln, type VulnDetail, type VulnTrackingStatus } from '../api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import ProjectFilterCombobox from '../components/ProjectFilterCombobox'
import VulnCalendar from '../components/VulnCalendar'
import VulnDetailDialog from '../components/VulnDetailDialog'
import VulnGroupList from '../components/VulnGroupList'
import { filterVulnGroups, groupVulnsByRootCause, vulnMatchesQuery, type VulnTierFilter } from '../lib/vulnGroups'
import { formatVulnType, saveBlob, VULN_TYPE_OPTIONS } from '../lib/utils'
import { readJsonCache, writeJsonCache } from '../lib/listCache'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const PAGE_SIZE = 50

const TIER_FILTER_LABEL: Record<VulnTierFilter, string> = {
  all: '全部分层',
  cve_candidate: '有 CVE 价值',
  low_impact: '低危害难利用',
}

const TRACKING_FILTER_LABEL: Record<'all' | VulnTrackingStatus, string> = {
  all: '全部标记',
  none: '未标记',
  submitted: '已提交',
  ignored: '已忽略',
}

export default function VulnsPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const detailId = id ? Number(id) : null
  const [filter, setFilter] = useState<'all' | 'confirmed' | 'false_positive' | 'pending_review'>('all')
  const [surfaceFilter, setSurfaceFilter] = useState<'all' | 'frontend' | 'backend'>('all')
  const [tierFilter, setTierFilter] = useState<VulnTierFilter>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [trackingFilter, setTrackingFilter] = useState<'all' | VulnTrackingStatus>('all')
  const [projectId, setProjectId] = useState<number | undefined>()
  const [projects, setProjects] = useState<ProjectName[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<number[]>([])
  const [marking, setMarking] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')

  const projectNameById = useMemo(() => {
    const map = new Map<number, string>()
    for (const p of projects) map.set(p.id, p.name)
    return map
  }, [projects])
  const projectKindById = useMemo(() => {
    const map = new Map<number, string>()
    for (const p of projects) {
      if (p.target_kind) map.set(p.id, p.target_kind)
    }
    return map
  }, [projects])

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const listQuery = useMemo(
    () => ({
      projectId,
      status: filter === 'all' ? undefined : filter,
      attackSurface: surfaceFilter === 'all' ? undefined : surfaceFilter,
      submissionTier: tierFilter === 'all' ? undefined : tierFilter,
      vulnType: typeFilter === 'all' ? undefined : typeFilter,
      trackingStatus: trackingFilter === 'all' ? undefined : trackingFilter,
      q: search,
    }),
    [projectId, filter, surfaceFilter, tierFilter, typeFilter, trackingFilter, search],
  )

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput), 300)
    return () => window.clearTimeout(timer)
  }, [searchInput])

  useEffect(() => {
    let cancelled = false
    api
      .listProjectNames()
      .then((names) => {
        if (!cancelled) setProjects(names)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  const refresh = useCallback(() => {
    const cacheKey = `vh:vulns:${page}:${JSON.stringify(listQuery)}`
    return api
      .listVulns({
        ...listQuery,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      .then((data) => {
        setVulns(data.items)
        setTotal(data.total)
        writeJsonCache(cacheKey, { items: data.items, total: data.total })
        const nextPageCount = Math.max(1, Math.ceil(data.total / PAGE_SIZE))
        if (page >= nextPageCount) setPage(Math.max(0, nextPageCount - 1))
      })
      .catch(() => {})
  }, [listQuery, page])

  useEffect(() => {
    const cacheKey = `vh:vulns:${page}:${JSON.stringify(listQuery)}`
    const cached = readJsonCache<{ items: Vuln[]; total: number }>(cacheKey)
    if (cached) {
      setVulns(cached.items)
      setTotal(cached.total)
    }
    return startVisibilityPoll(refresh, 5000)
  }, [listQuery, page, refresh])

  useEffect(() => {
    setPage(0)
    setSelected([])
  }, [listQuery])

  const searchedVulns = useMemo(
    () => vulns.filter((v) => vulnMatchesQuery(v, search, projectNameById)),
    [vulns, search, projectNameById],
  )
  const cveCandidateIds = useMemo(
    () => searchedVulns.filter((v) => v.submission_tier === 'cve_candidate').map((v) => v.id),
    [searchedVulns],
  )
  const openListItem = detailId != null ? vulns.find((v) => v.id === detailId) : undefined
  const openProject = openListItem
    ? projects.find((p) => p.id === openListItem.project_id)
    : undefined

  const surfaceFilterLabel =
    surfaceFilter === 'frontend' ? '前台漏洞' : surfaceFilter === 'backend' ? '后台漏洞' : '全部前后台'

  async function downloadIds(ids: number[], filename: string) {
    if (!ids.length) return
    saveBlob(await api.downloadVulns(ids), filename)
  }

  async function matchingVulns() {
    const all = await api.listAllVulns(listQuery)
    const searched = all.filter((v) => vulnMatchesQuery(v, search, projectNameById))
    return filterVulnGroups(groupVulnsByRootCause(searched), tierFilter).flatMap((g) => [
      g.primary,
      ...g.others,
    ])
  }

  async function download() {
    const ids = selected.length ? selected : (await matchingVulns()).map((v) => v.id)
    await downloadIds(ids, 'vulns.zip')
  }

  async function downloadCveCandidates() {
    const ids = selected.length
      ? selected.filter((sid) => cveCandidateIds.includes(sid))
      : (await matchingVulns())
          .filter((v) => v.submission_tier === 'cve_candidate')
          .map((v) => v.id)
    await downloadIds(ids, 'vulns-cve-candidates.zip')
  }

  function applyTracking(updated: Array<Pick<Vuln, 'id' | 'tracking_status'>>) {
    const byId = new Map(updated.map((v) => [v.id, (v.tracking_status ?? 'none') as VulnTrackingStatus]))
    setVulns((prev) =>
      prev.map((v) => {
        const next = byId.get(v.id)
        return next == null ? v : { ...v, tracking_status: next }
      }),
    )
  }

  function onDetailUpdated(detail: VulnDetail) {
    setVulns((prev) =>
      prev.map((v) =>
        v.id === detail.id
          ? {
              ...v,
              tracking_status: detail.tracking_status,
              evidence_level: detail.evidence_level,
              verifier_status: detail.verifier_status,
              verifier_verified_url: detail.verifier_verified_url,
            }
          : v,
      ),
    )
  }

  async function markIds(ids: number[], tracking_status: VulnTrackingStatus) {
    if (!ids.length || marking) return
    setMarking(true)
    try {
      if (ids.length === 1) {
        applyTracking([await api.updateVulnTracking(ids[0], tracking_status)])
      } else {
        applyTracking(await api.markVulns(ids, tracking_status))
      }
      await refresh()
    } catch {
      /* ignore transient */
    } finally {
      setMarking(false)
    }
  }

  async function markSelected(tracking_status: VulnTrackingStatus) {
    await markIds(selected, tracking_status)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">漏洞产出</h1>
          <p className="text-sm text-slate-400">
            按项目、状态、价值分层与提交标记筛选；同根因报告折叠在危害最大的条目下。上方日历按产出日汇总确认与误报。
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('submitted')}
          >
            标记已提交
          </Button>
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('ignored')}
          >
            标记已忽略
          </Button>
          <Button
            variant="outline"
            disabled={!selected.length || marking}
            onClick={() => markSelected('none')}
          >
            取消标记
          </Button>
          <Button variant="outline" onClick={downloadCveCandidates} disabled={!selected.length && total === 0}>
            仅下载有 CVE 价值
          </Button>
          <Button onClick={download}>批量下载</Button>
        </div>
      </div>

      <VulnCalendar
        projectId={projectId}
        projectNameById={projectNameById}
        projectKindById={projectKindById}
        onOpenVuln={(vid) => navigate(`/vulns/${vid}`)}
      />

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pr-8 pl-8"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="搜索标题、路径、类型、编号、项目…"
          aria-label="搜索漏洞"
        />
        {searchInput ? (
          <button
            type="button"
            className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
            aria-label="清除搜索"
            onClick={() => setSearchInput('')}
          >
            <XIcon className="size-4" />
          </button>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <ProjectFilterCombobox projects={projects} projectId={projectId} onProjectIdChange={setProjectId} />
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
        <Select
          value={typeFilter}
          onValueChange={(value) => {
            if (value == null) return
            setTypeFilter(value)
          }}
        >
          <SelectTrigger className="w-auto min-w-36">
            <SelectValue>{typeFilter === 'all' ? '全部类型' : formatVulnType(typeFilter)}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            <SelectItem value="all">全部类型</SelectItem>
            {VULN_TYPE_OPTIONS.map(([id, label]) => (
              <SelectItem key={id} value={id}>
                {label}
              </SelectItem>
            ))}
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
        <Select
          value={trackingFilter}
          onValueChange={(value) => {
            if (value == null) return
            setTrackingFilter(value as typeof trackingFilter)
          }}
        >
          <SelectTrigger className="w-auto min-w-32">
            <SelectValue>{TRACKING_FILTER_LABEL[trackingFilter]}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            {(Object.keys(TRACKING_FILTER_LABEL) as Array<keyof typeof TRACKING_FILTER_LABEL>).map((k) => (
              <SelectItem key={k} value={k}>
                {TRACKING_FILTER_LABEL[k]}
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
          vulns={searchedVulns}
          tierFilter={tierFilter}
          activeId={detailId}
          selectedIds={selected}
          expandAll={Boolean(search.trim())}
          emptyText={search.trim() ? '无匹配漏洞' : '暂无数据'}
          onToggleSelect={(vid, checked) =>
            setSelected((prev) => (checked ? [...prev, vid] : prev.filter((x) => x !== vid)))
          }
          projectNameById={projectNameById}
          projectKindById={projectKindById}
        />
      </Card>

      {total > PAGE_SIZE ? (
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
          <span>
            第 {page + 1} / {pageCount} 页，共 {total} 条
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              aria-label="上一页"
            >
              <ChevronLeftIcon className="size-4" />
              上一页
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page + 1 >= pageCount}
              onClick={() => setPage((p) => p + 1)}
              aria-label="下一页"
            >
              下一页
              <ChevronRightIcon className="size-4" />
            </Button>
          </div>
        </div>
      ) : null}

      <VulnDetailDialog
        vulnId={detailId}
        onClose={() => navigate('/vulns', { replace: true })}
        onSelectVuln={(vid) => navigate(`/vulns/${vid}`)}
        projectName={
          openListItem?.project_name ||
          (openListItem ? projectNameById.get(openListItem.project_id) : undefined)
        }
        dynamicVerifyMode={openProject?.dynamic_verify_mode}
        dynamicVerifyEnabled={openProject?.dynamic_verify_enabled}
        onUpdated={onDetailUpdated}
      />
    </div>
  )
}
