import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2Icon } from 'lucide-react'
import { api, type VerifierConsentItem } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { formatDateTime, formatSeverity, formatSeverityScore, severityScoreBadgeClass } from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

export default function VerifierConsentPage() {
  const [items, setItems] = useState<VerifierConsentItem[]>([])
  const [instructions, setInstructions] = useState<Record<number, string>>({})
  const [busyId, setBusyId] = useState<number | null>(null)
  const [error, setError] = useState('')

  const refresh = () =>
    api
      .listVerifierConsent()
      .then(setItems)
      .catch(() => {})

  useEffect(() => startVisibilityPoll(refresh, 4000), [])

  const submit = async (id: number, action: 'skip' | 'continue') => {
    setBusyId(id)
    setError('')
    try {
      await api.resolveVerifierConsent(id, action, instructions[id] || '')
      setInstructions((prev) => {
        const next = { ...prev }
        delete next[id]
        return next
      })
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">验证确认</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          互联网复测可能中断或篡改对方业务时，Verifier 会停在这里询问你。等待确认不耽误审计项目完成。
        </p>
      </div>

      {error ? (
        <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      {items.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            当前没有需要确认的互联网验证。有危害的复测会自动出现在此列表。
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {items.map((item) => {
            const busy = busyId === item.id
            return (
              <Card key={item.id}>
                <CardHeader className="pb-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1">
                      <CardTitle className="text-base">
                        <Link className="hover:underline" to={`/vulns/${item.id}`}>
                          #{item.id} {item.title}
                        </Link>
                      </CardTitle>
                      <CardDescription>
                        项目{' '}
                        <Link className="hover:underline" to={`/projects/${item.project_id}`}>
                          {item.project_name || `#${item.project_id}`}
                        </Link>
                        {' · '}
                        {formatDateTime(item.updated_at)}
                      </CardDescription>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline">待用户确认</Badge>
                      {item.vuln_type ? <Badge variant="secondary">{item.vuln_type}</Badge> : null}
                      {item.severity_score != null ? (
                        <Badge className={severityScoreBadgeClass(item.severity_score, item.cvss_vector)} title={item.cvss_vector || undefined}>
                          {formatSeverityScore(item.severity_score, item.severity, item.cvss_vector)}
                        </Badge>
                      ) : formatSeverity(item.severity) ? (
                        <Badge variant="outline">{formatSeverity(item.severity)}</Badge>
                      ) : null}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-100/90 whitespace-pre-wrap">
                    {item.verifier_ask_reason || 'Verifier 请求确认是否继续互联网复测。'}
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground" htmlFor={`inst-${item.id}`}>
                      自定义指示（可选，点「继续验证」时生效）
                    </label>
                    <Textarea
                      id={`inst-${item.id}`}
                      rows={3}
                      placeholder="例如：只测只读探测、避开写库 payload、仅打非生产目标…"
                      value={instructions[item.id] || ''}
                      disabled={busy}
                      onChange={(e) =>
                        setInstructions((prev) => ({ ...prev, [item.id]: e.target.value }))
                      }
                    />
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      disabled={busy}
                      onClick={() => submit(item.id, 'skip')}
                    >
                      {busy ? <Loader2Icon className="mr-2 h-4 w-4 animate-spin" /> : null}
                      跳过
                    </Button>
                    <Button disabled={busy} onClick={() => submit(item.id, 'continue')}>
                      {busy ? <Loader2Icon className="mr-2 h-4 w-4 animate-spin" /> : null}
                      继续验证
                    </Button>
                    <Link
                      className="inline-flex h-8 items-center rounded-lg px-2.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
                      to={`/vulns/${item.id}`}
                    >
                      查看漏洞
                    </Link>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
