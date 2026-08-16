import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api, type Project, type Vuln, type VulnDetail } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn, formatAttackSurface, formatDateTime } from '../lib/utils'

const STATUS_LABEL: Record<string, string> = {
  pending_review: '待审',
  confirmed: '已确认',
  false_positive: '误报',
  static_only: '仅静态',
  returned: '已打回',
}

export default function VulnsPage() {
  const { id } = useParams()
  const detailId = id ? Number(id) : null
  const [filter, setFilter] = useState<'all' | 'confirmed' | 'false_positive' | 'pending_review'>('all')
  const [projectId, setProjectId] = useState<number | undefined>()
  const [projects, setProjects] = useState<Project[]>([])
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [detail, setDetail] = useState<VulnDetail | null>(null)
  const [selected, setSelected] = useState<number[]>([])

  const projectNameById = useMemo(() => {
    const map = new Map<number, string>()
    for (const p of projects) map.set(p.id, p.name)
    return map
  }, [projects])

  const refresh = () =>
    api
      .listVulns(projectId, filter === 'all' ? undefined : filter)
      .then(setVulns)
      .catch(() => {})

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [filter, projectId])

  useEffect(() => {
    setSelected([])
  }, [filter, projectId])

  useEffect(() => {
    if (!detailId) {
      setDetail(null)
      return
    }
    api.getVuln(detailId).then(setDetail).catch(() => setDetail(null))
  }, [detailId])

  const filtered = useMemo(() => vulns, [vulns])
  const detailSurface = formatAttackSurface(detail?.attack_surface, detail?.required_account)
  const detailProject =
    detail?.project_name ||
    (detail ? projectNameById.get(detail.project_id) : undefined) ||
    (detail ? `项目 ${detail.project_id}` : '')
  const projectFilterLabel = projectId == null ? '全部项目' : projectNameById.get(projectId) || `项目 ${projectId}`

  async function download() {
    const ids = selected.length ? selected : filtered.map((v) => v.id)
    if (!ids.length) return
    const blob = await api.downloadVulns(ids)
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'vulns.zip'
    a.click()
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">漏洞产出</h1>
          <p className="text-sm text-slate-400">按项目与状态筛选，支持批量下载报告。</p>
        </div>
        <Button onClick={download}>批量下载</Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={projectId == null ? '__all__' : String(projectId)}
          onValueChange={(value) => {
            if (value == null) return
            setProjectId(value === '__all__' ? undefined : Number(value))
          }}
        >
          <SelectTrigger className="w-auto min-w-52">
            <SelectValue>{projectFilterLabel}</SelectValue>
          </SelectTrigger>
          <SelectContent alignItemWithTrigger={false} align="start" className="w-(--anchor-width)">
            <SelectItem value="__all__">全部项目</SelectItem>
            {projects.map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
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

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(16rem,18rem)_minmax(0,1fr)]">
        <Card className="max-h-[calc(100vh-13rem)] gap-0 divide-y divide-border overflow-auto py-0">
          {filtered.map((v) => {
            const surface = formatAttackSurface(v.attack_surface, v.required_account)
            const projectName = v.project_name || projectNameById.get(v.project_id) || `项目 ${v.project_id}`
            return (
              <div
                key={v.id}
                className={cn(
                  'flex items-start gap-2 px-2.5 py-2.5',
                  detailId === v.id && 'bg-muted',
                )}
              >
                <Checkbox
                  className="mt-1 shrink-0"
                  checked={selected.includes(v.id)}
                  onCheckedChange={(checked) =>
                    setSelected((prev) =>
                      checked === true ? [...prev, v.id] : prev.filter((x) => x !== v.id),
                    )
                  }
                />
                <Link to={`/vulns/${v.id}`} className="min-w-0 flex-1 hover:underline">
                  <div className="break-words font-medium leading-snug">{v.title}</div>
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
                    <span className="text-xs text-slate-400">
                      #{v.id} · {projectName} · {v.vuln_type} · {v.severity}
                      {surface ? ` · ${surface}` : ''} · {formatDateTime(v.created_at)}
                    </span>
                  </div>
                </Link>
              </div>
            )
          })}
          {filtered.length === 0 ? <div className="p-4 text-sm text-muted-foreground">暂无数据</div> : null}
        </Card>

        <Card className="min-w-0 max-h-[calc(100vh-13rem)] overflow-auto">
          <CardContent className="p-5">
          {detail ? (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold">{detail.title}</h2>
              <div className="text-xs text-slate-400">
                {detailProject} · 产出时间 {formatDateTime(detail.created_at)}
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                <Badge variant="outline">{detail.vuln_type}</Badge>
                <Badge variant="warning">{detail.severity}</Badge>
                <Badge variant="info">{detail.status}</Badge>
                {detail.evidence_level ? <Badge variant="outline">{detail.evidence_level}</Badge> : null}
                {detailSurface ? <Badge variant="info">{detailSurface}</Badge> : null}
              </div>
              <div className="vh-md">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {detail.report_md || detail.source_sink || '_无报告_'}
                </ReactMarkdown>
              </div>
              {detail.http_request ? (
                <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.http_request}</pre>
              ) : null}
              {detail.poc_code ? (
                <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.poc_code}</pre>
              ) : null}
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">选择左侧漏洞查看详情</div>
          )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
