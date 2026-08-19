import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type CustomAuditMode, type Project } from '../api'
import { AuditModeSelect } from '../components/AuditModeSelect'
import { DeleteProjectButton } from '../components/DeleteProjectButton'
import { GithubLink } from '../components/GithubLink'
import { DynamicVerifyToggle, normalizeDynamicVerifyMode, type DynamicVerifyMode } from '../components/DynamicVerifyToggle'
import { ManualLabToggle } from '../components/ManualLabFields'
import { VerifierToggle } from '../components/VerifierToggle'
import { AuditFlowPreview } from '../components/AuditFlowPreview'
import { MiningPathSelect } from '../components/MiningPathSelect'
import { ProjectModelSelect } from '../components/ProjectModelSelect'
import PhaseFlow from '../components/PhaseFlow'
import { WeightExtBadges } from '../components/WeightExtBadges'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { githubRepoHref } from '../lib/github'
import { formatAuditMode, formatDateTime, formatMiningPaths, formatMiningProgress, formatProjectRunStatus, formatTokenUsage, type AuditMode } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [url, setUrl] = useState('')
  const [auditMode, setAuditMode] = useState<AuditMode>('bounty')
  const [customModes, setCustomModes] = useState<CustomAuditMode[]>([])
  const [customModeId, setCustomModeId] = useState<number | null>(null)
  const [manualLab, setManualLab] = useState(false)
  const [manualLabPrompt, setManualLabPrompt] = useState('')
  const [dynamicVerifyMode, setDynamicVerifyMode] = useState<DynamicVerifyMode>('off')
  const [verifierEnabled, setVerifierEnabled] = useState(false)
  const [heuristicEnabled, setHeuristicEnabled] = useState(true)
  const [heuristicLite, setHeuristicLite] = useState(false)
  const [fastEnabled, setFastEnabled] = useState(false)
  const [bypassEnabled, setBypassEnabled] = useState(false)
  const [llmModel, setLlmModel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const dynamicVerifyEnabled = dynamicVerifyMode !== 'off'
  const labMode = dynamicVerifyMode === 'lab'
  const selectedCustomName = customModes.find((m) => m.id === customModeId)?.name

  const refresh = () => api.listProjects().then(setProjects).catch((e) => setError(String(e)))

  useEffect(() => startVisibilityPoll(refresh, 4000), [])
  useEffect(() => {
    api.listCustomAuditModes().then(setCustomModes).catch(() => setCustomModes([]))
  }, [])

  async function createGithub() {
    if (!url.trim()) return
    if (auditMode === 'custom' && customModeId == null) {
      setError('请先选择自定义审计模式（可在设置页创建）')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.createGithub(url.trim(), '', auditMode, {
        custom_audit_mode_id: auditMode === 'custom' ? customModeId : null,
        manual_lab: labMode && manualLab,
        manual_lab_prompt: labMode && manualLab ? manualLabPrompt : '',
        verifier_enabled: verifierEnabled,
        dynamic_verify_enabled: dynamicVerifyEnabled,
        dynamic_verify_mode: dynamicVerifyMode,
        heuristic_enabled: heuristicEnabled,
        heuristic_lite: heuristicLite,
        fast_enabled: fastEnabled,
        bypass_enabled: bypassEnabled,
        llm_model: llmModel,
      })
      setUrl('')
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function onZip(file: File | null) {
    if (!file) return
    if (auditMode === 'custom' && customModeId == null) {
      setError('请先选择自定义审计模式（可在设置页创建）')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.uploadZip(file, '', auditMode, {
        custom_audit_mode_id: auditMode === 'custom' ? customModeId : null,
        manual_lab: labMode && manualLab,
        manual_lab_prompt: labMode && manualLab ? manualLabPrompt : '',
        verifier_enabled: verifierEnabled,
        dynamic_verify_enabled: dynamicVerifyEnabled,
        dynamic_verify_mode: dynamicVerifyMode,
        heuristic_enabled: heuristicEnabled,
        heuristic_lite: heuristicLite,
        fast_enabled: fastEnabled,
        bypass_enabled: bypassEnabled,
        llm_model: llmModel,
      })
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="w-full space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">审计项目</h1>
        <p className="mt-1 text-sm text-slate-400">导入 GitHub 仓库或源码 zip，启动白盒审计。创建时选择赏金/全量/自定义（自定义需先在设置页配置），并可勾选启发式挖掘（可选轻量，只挖权重 100）、快速扫描与历史漏洞绕过；默认只开启发式。每个项目可单独选择模型，不选则使用设置里的全局模型。验证方式默认关闭（仅静态），可改为靶场动态或局部验证；互联网验证默认关闭。</p>
      </div>

      <Card className="w-full">
        <CardContent className="w-full">
        <div className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)] xl:items-start">
            <div className="space-y-3">
              <AuditModeSelect
                value={auditMode}
                customModeId={customModeId}
                customModes={customModes}
                customModeName={selectedCustomName}
                onValueChange={setAuditMode}
                onCustomModeIdChange={setCustomModeId}
              />
              <ProjectModelSelect value={llmModel} onValueChange={setLlmModel} />
              <MiningPathSelect
                heuristicEnabled={heuristicEnabled}
                heuristicLite={heuristicLite}
                fastEnabled={fastEnabled}
                bypassEnabled={bypassEnabled}
                onChange={({ heuristicEnabled: nextH, heuristicLite: nextL, fastEnabled: nextF, bypassEnabled: nextB }) => {
                  setHeuristicEnabled(nextH)
                  setHeuristicLite(nextL)
                  setFastEnabled(nextF)
                  setBypassEnabled(nextB)
                }}
              />
              <DynamicVerifyToggle mode={dynamicVerifyMode} onModeChange={setDynamicVerifyMode} />
              {labMode ? (
                <ManualLabToggle
                  enabled={manualLab}
                  prompt={manualLabPrompt}
                  onEnabledChange={setManualLab}
                  onPromptChange={setManualLabPrompt}
                />
              ) : null}
              <VerifierToggle enabled={verifierEnabled} onEnabledChange={setVerifierEnabled} />
            </div>
            <AuditFlowPreview
              className="xl:sticky xl:top-[4.25rem]"
              auditMode={auditMode}
              dynamicVerifyEnabled={dynamicVerifyEnabled}
              dynamicVerifyMode={dynamicVerifyMode}
              manualLab={manualLab}
              verifierEnabled={verifierEnabled}
              heuristicEnabled={heuristicEnabled}
              heuristicLite={heuristicLite}
              fastEnabled={fastEnabled}
              bypassEnabled={bypassEnabled}
            />
          </div>
          <div className="grid w-full gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto]">
            <Input
              className="w-full"
              placeholder="https://github.com/owner/repo"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <Button disabled={busy} onClick={createGithub}>
              从 GitHub 创建
            </Button>
            <Label className="inline-flex h-8 cursor-pointer items-center justify-center rounded-lg border border-input px-3 text-sm font-medium hover:bg-muted">
              上传 Zip
              <Input
                type="file"
                accept=".zip"
                className="hidden"
                onChange={(e) => onZip(e.target.files?.[0] || null)}
              />
            </Label>
          </div>
        </div>
        {error ? <p className="mt-2 text-sm text-red-300">{error}</p> : null}
        </CardContent>
      </Card>

      <div className="flex w-full flex-col gap-3">
        {projects.map((p) => {
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
        {projects.length === 0 ? (
          <Card className="w-full">
            <CardContent className="text-sm text-muted-foreground">暂无项目，先导入一个 Web 源码仓。</CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  )
}
