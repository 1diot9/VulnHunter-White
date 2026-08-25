import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { SearchIcon, XIcon } from 'lucide-react'
import { api, type Project, type Vuln, type VulnDetail, type VulnTrackingStatus } from '../api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import ProjectFilterCombobox from '../components/ProjectFilterCombobox'
import VulnDetailDialog from '../components/VulnDetailDialog'
import VulnGroupList from '../components/VulnGroupList'
import { filterVulnGroups, groupVulnsByRootCause, vulnMatchesQuery, type VulnTierFilter } from '../lib/vulnGroups'
import { saveBlob } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const TIER_FILTER_LABEL: Record<VulnTierFilter, string> = {
  all: '全部分层',
  cve_candidate: '有 CVE 价值',
  low_impact: '低危害难利用',
  duplicate_grouped: '同根因重复',
  untiered: '未分层',
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
  const [trackingFilter, setTrackingFilter] = useState<'all' | VulnTrackingStatus>('all')
  const [projectId, setProjectId] = useState<number | undefined>()
  const [projects, setProjects] = useState<Project[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [selected, setSelected] = useState<number[]>([])
  const [marking, setMarking] = useState(false)
  const [search, setSearch] = useState('')

  const projectNameById = useMemo(() => {
    const map = new Map<number, string>()
    for (const p of projects) map.set(p.id, p.name)
    return map
  }, [projects])

  const refresh = () =>
    api
      .listVulns(
        projectId,
        filter === 'all' ? undefined : filter,
        surfaceFilter === 'all' ? undefined : surfaceFilter,
        undefined,
        undefined,
        trackingFilter === 'all' ? undefined : trackingFilter,
      )
      .then(setVulns)
      .catch(() => {})

  useEffect(() => {
    api.listAllProjects().then(setProjects).catch(() => {})
  }, [])

  useEffect(() => startVisibilityPoll(refresh, 5000), [filter, projectId, surfaceFilter, trackingFilter])

  useEffect(() => {
    setSelected([])
  }, [filter, projectId, surfaceFilter, tierFilter, trackingFilter])

  const searchedVulns = useMemo(
    () => vulns.filter((v) => vulnMatchesQuery(v, search, projectNameById)),
    [vulns, search, projectNameById],
  )
  const visibleVulns = useMemo(
    () =>
      filterVulnGroups(groupVulnsByRootCause(searchedVulns), tierFilter).flatMap((g) => [
        g.primary,
        ...g.others,
      ]),
    [searchedVulns, tierFilter],
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

  async function download() {
    const ids = selected.length ? selected : visibleVulns.map((v) => v.id)
    await downloadIds(ids, 'vulns.zip')
  }

  async function downloadCveCandidates() {
    const ids = selected.length
      ? selected.filter((sid) => cveCandidateIds.includes(sid))
      : cveCandidateIds
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
            按项目、状态、价值分层与提交标记筛选；同根因报告折叠在危害最大的条目下。
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
          <Button variant="outline" onClick={downloadCveCandidates} disabled={!cveCandidateIds.length && !selected.length}>
            仅下载有 CVE 价值
          </Button>
          <Button onClick={download}>批量下载</Button>
        </div>
      </div>

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pr-8 pl-8"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="搜索标题、路径、类型、编号、项目…"
          aria-label="搜索漏洞"
        />
        {search ? (
          <button
            type="button"
            className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:text-foreground"
            aria-label="清除搜索"
            onClick={() => setSearch('')}
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
        />
      </Card>

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
