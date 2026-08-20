import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { PlusIcon, SearchIcon, XIcon } from 'lucide-react'
import { api, type Project } from '../api'
import { CreateProjectDialog } from '../components/CreateProjectDialog'
import { DeleteProjectButton } from '../components/DeleteProjectButton'
import { GithubLink } from '../components/GithubLink'
import { normalizeDynamicVerifyMode } from '../components/DynamicVerifyToggle'
import PhaseFlow from '../components/PhaseFlow'
import { WeightExtBadges } from '../components/WeightExtBadges'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { githubRepoHref, githubRepoLabel } from '../lib/github'
import { formatAuditMode, formatDateTime, formatMiningPaths, formatMiningProgress, formatProjectRunStatus, formatProjectStatus, formatTokenUsage } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

function CreateProjectButton({ onClick }: { onClick: () => void }) {
  return (
    <Button
      size="lg"
      className="h-11 shrink-0 gap-2 px-5 text-base font-semibold shadow-lg shadow-primary/25 ring-2 ring-primary/40"
      onClick={onClick}
    >
      <PlusIcon className="size-5" />
      创建项目
    </Button>
  )
}

function projectMatchesQuery(p: Project, query: string): boolean {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!tokens.length) return true
  const haystack = [
    p.name,
    String(p.id),
    `#${p.id}`,
    p.identity,
    p.source_url,
    p.source_type,
    p.llm_model || '全局模型',
    formatAuditMode(p.audit_mode, p.custom_audit_mode_name),
    p.custom_audit_mode_name,
    formatMiningPaths(p),
    formatProjectRunStatus(p.status, p.project_paused),
    formatProjectStatus(p.status),
    githubRepoLabel(p),
  ]
    .filter(Boolean)
    .join('\n')
    .toLowerCase()
  return tokens.every((token) => haystack.includes(token))
}

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)

  const refresh = () => api.listProjects().then(setProjects).catch((e) => setError(String(e)))

  useEffect(() => startVisibilityPoll(refresh, 4000), [])

  const filteredProjects = useMemo(
    () => projects.filter((p) => projectMatchesQuery(p, search)),
    [projects, search],
  )

  return (
    <div className="w-full space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">审计项目</h1>
          <p className="mt-1 text-sm text-slate-400">导入 GitHub 仓库或源码 zip，启动白盒审计。</p>
        </div>
        <CreateProjectButton onClick={() => setCreateOpen(true)} />
      </div>

      <CreateProjectDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={refresh}
      />

      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pr-8 pl-8"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="搜索项目名称、仓库、模式、模型、状态…"
          aria-label="搜索审计项目"
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

      {error ? <p className="text-sm text-red-300">{error}</p> : null}

      <div className="flex w-full flex-col gap-3">
        {filteredProjects.map((p) => {
          const runStatus = formatProjectRunStatus(p.status, p.project_paused)
          return (
          <Card key={p.id} className="w-full">
            <CardHeader>
              <div className="min-w-0">
                <CardTitle>
                  <Link to={`/projects/${p.id}`} className="hover:underline">
                    {p.name}
                  </Link>
                </CardTitle>
                <CardDescription className="mt-1 flex min-w-0 flex-wrap items-center gap-x-1.5 text-xs">
                  <span>{formatAuditMode(p.audit_mode, p.custom_audit_mode_name)}</span>
                  <span>·</span>
                  <span>{p.llm_model || '全局模型'}</span>
                  <span>·</span>
                  <span>{formatMiningPaths(p)}</span>
                  <span>·</span>
                  {githubRepoHref(p) ? (
                    <GithubLink project={p} className="min-w-0" />
                  ) : (
                    <span className="truncate">{p.identity || p.source_url || p.source_type}</span>
                  )}
                  <span>·</span>
                  <span>{formatDateTime(p.created_at)}</span>
                </CardDescription>
              </div>
              <CardAction>
                <div className="flex items-center gap-2">
                  <GithubLink project={p} variant="button" />
                  <Badge
                    variant={
                      runStatus === '已完成'
                        ? 'success'
                        : runStatus === '已停止'
                          ? 'destructive'
                          : runStatus === '已暂停'
                            ? 'warning'
                            : 'info'
                    }
                  >
                    {runStatus}
                  </Badge>
                  <DeleteProjectButton
                    projectId={p.id}
                    projectName={p.name}
                    size="sm"
                    onDeleted={refresh}
                  />
                </div>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-3">
              <PhaseFlow
                phase={p.phase}
                status={p.status}
                reconDone={p.recon_done}
                filesAudited={p.files_audited}
                filesSkipped={p.files_skipped}
                filesTotal={p.files_total}
                filesWeight100={p.files_weight100}
                filesWeight100Audited={p.files_weight100_audited}
                workerRounds={p.worker_rounds}
                vulnPending={p.vuln_pending}
                reconSubphases={p.recon_subphases}
                labSetupDone={p.lab_setup_done}
                manualLab={Boolean(p.manual_lab_prompt)}
                dynamicVerifyEnabled={p.dynamic_verify_enabled}
                dynamicVerifyMode={normalizeDynamicVerifyMode(p.dynamic_verify_mode, p.dynamic_verify_enabled)}
                verifierEnabled={p.verifier_enabled}
                verifierPending={p.verifier_pending}
                attackChainEnabled={p.attack_chain_enabled}
                attackChainDone={p.attack_chain_done}
                heuristicEnabled={p.heuristic_enabled}
                heuristicLite={p.heuristic_lite}
                fastEnabled={p.fast_enabled}
                fastQueueFrozen={p.fast_queue_frozen}
                sinksQueued={p.sinks_queued}
                sinksDone={p.sinks_done}
                bypassEnabled={p.bypass_enabled}
                bypassQueueFrozen={p.bypass_queue_frozen}
                bypassQueued={p.bypass_queued}
                bypassDone={p.bypass_done}
              />
              <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                <span>确认 {p.vuln_confirmed}</span>
                <span>待审 {p.vuln_pending}</span>
                <span>误报 {p.vuln_false_positive}</span>
                <span>{formatMiningProgress(p)}</span>
                <span>{formatTokenUsage(p)}</span>
              </div>
              <WeightExtBadges exts={p.weight_exts} />
              {p.error ? <p className="text-xs text-red-300">{p.error}</p> : null}
            </CardContent>
          </Card>
          )
        })}
        {filteredProjects.length === 0 ? (
          <Card className="w-full">
            <CardContent className="flex flex-col items-start gap-3 py-8 text-sm text-muted-foreground">
              {search.trim() ? (
                '无匹配项目'
              ) : (
                <>
                  <p>暂无项目。点击「创建项目」导入 GitHub 仓库或源码 zip。</p>
                  <CreateProjectButton onClick={() => setCreateOpen(true)} />
                </>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  )
}
