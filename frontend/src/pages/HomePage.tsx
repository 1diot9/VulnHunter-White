import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, type Project } from '../api'
import PhaseFlow from '../components/PhaseFlow'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { formatDateTime, formatFileProgress, formatTokenUsage } from '../lib/utils'

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const refresh = () => api.listProjects().then(setProjects).catch((e) => setError(String(e)))

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 4000)
    return () => clearInterval(t)
  }, [])

  async function createGithub() {
    if (!url.trim()) return
    setBusy(true)
    setError('')
    try {
      await api.createGithub(url.trim())
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
      await api.uploadZip(file)
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">审计项目</h1>
        <p className="mt-1 text-sm text-slate-400">导入 GitHub 仓库或源码 zip，启动白盒启发式审计。</p>
      </div>

      <Card>
        <CardContent>
        <div className="grid gap-3 md:grid-cols-[1fr_auto_auto]">
          <Input
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
        {error ? <p className="mt-2 text-sm text-red-300">{error}</p> : null}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {projects.map((p) => (
          <Card key={p.id}>
            <CardHeader>
              <div>
                <CardTitle>
                  <Link to={`/projects/${p.id}`} className="hover:underline">
                  {p.name}
                </Link>
                </CardTitle>
                <CardDescription className="mt-1 text-xs">
                  {p.identity || p.source_url || p.source_type} · {formatDateTime(p.created_at)}
                </CardDescription>
              </div>
              <CardAction>
              <Badge
                variant={
                  p.status === 'completed'
                    ? 'success'
                    : p.status === 'error' || p.status === 'cancelled'
                      ? 'destructive'
                      : p.status === 'paused'
                        ? 'warning'
                        : 'info'
                }
              >
                {p.status}
              </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-3">
            <div>
              <PhaseFlow
                phase={p.phase}
                status={p.status}
                reconDone={p.recon_done}
                filesAudited={p.files_audited}
                filesSkipped={p.files_skipped}
                filesTotal={p.files_total}
                vulnPending={p.vuln_pending}
                reconSubphases={p.recon_subphases}
              />
            </div>
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
        ))}
        {projects.length === 0 ? (
          <Card className="md:col-span-2">
            <CardContent className="text-sm text-muted-foreground">暂无项目，先导入一个 Web 源码仓。</CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  )
}
