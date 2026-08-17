import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type Project } from '../api'
import { AuditModeSelect } from '../components/AuditModeSelect'
import { ManualLabToggle } from '../components/ManualLabFields'
import PhaseFlow from '../components/PhaseFlow'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { formatAuditMode, formatDateTime, formatFileProgress, formatProjectRunStatus, formatTokenUsage } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [url, setUrl] = useState('')
  const [auditMode, setAuditMode] = useState<'bounty' | 'full'>('bounty')
  const [manualLab, setManualLab] = useState(false)
  const [manualLabPrompt, setManualLabPrompt] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const refresh = () => api.listProjects().then(setProjects).catch((e) => setError(String(e)))

  useEffect(() => startVisibilityPoll(refresh, 4000), [])

  async function createGithub() {
    if (!url.trim()) return
    setBusy(true)
    setError('')
    try {
      await api.createGithub(url.trim(), '', auditMode, {
        manual_lab: manualLab,
        manual_lab_prompt: manualLab ? manualLabPrompt : '',
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
    setBusy(true)
    setError('')
    try {
      await api.uploadZip(file, '', auditMode, {
        manual_lab: manualLab,
        manual_lab_prompt: manualLab ? manualLabPrompt : '',
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
        <p className="mt-1 text-sm text-slate-400">导入 GitHub 仓库或源码 zip，启动白盒启发式审计。创建时选择挖掘模式，默认赏金模式。</p>
      </div>

      <Card className="w-full">
        <CardContent className="w-full">
        <div className="space-y-3">
          <AuditModeSelect value={auditMode} onValueChange={setAuditMode} />
          <ManualLabToggle
            enabled={manualLab}
            prompt={manualLabPrompt}
            onEnabledChange={setManualLab}
            onPromptChange={setManualLabPrompt}
          />
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
                <CardDescription className="mt-1 truncate text-xs">
                  {formatAuditMode(p.audit_mode)} · {p.identity || p.source_url || p.source_type} · {formatDateTime(p.created_at)}
                </CardDescription>
              </div>
              <CardAction>
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
                workerRounds={p.worker_rounds}
                vulnPending={p.vuln_pending}
                reconSubphases={p.recon_subphases}
                labSetupDone={p.lab_setup_done}
                manualLab={p.manual_lab}
              />
              <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
                <span>确认 {p.vuln_confirmed}</span>
                <span>待审 {p.vuln_pending}</span>
                <span>误报 {p.vuln_false_positive}</span>
                <span>{formatFileProgress(p)}</span>
                <span>{formatTokenUsage(p)}</span>
              </div>
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
