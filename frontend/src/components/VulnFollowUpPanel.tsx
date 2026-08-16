import { lazy, Suspense, useEffect, useState } from 'react'
import { api, type VulnFollowUpThread } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { formatDateTime } from '../lib/utils'

const MarkdownView = lazy(() => import('./MarkdownView'))

function displayError(err: unknown) {
  const text = err instanceof Error ? err.message : String(err || '')
  try {
    const data = JSON.parse(text)
    return String(data.detail || text)
  } catch {
    return text || '请求失败'
  }
}

export default function VulnFollowUpPanel({ vulnId }: { vulnId: number }) {
  const [thread, setThread] = useState<VulnFollowUpThread | null>(null)
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    setThread(null)
    setError('')
    setQuestion('')
    setLoading(true)
    api
      .listVulnFollowUps(vulnId)
      .then((data) => {
        if (alive) setThread(data)
      })
      .catch((err) => {
        if (alive) setError(displayError(err))
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [vulnId])

  async function submit() {
    const q = question.trim()
    if (!q || submitting || !thread?.reviewer_context_available) return
    setSubmitting(true)
    setError('')
    try {
      const next = await api.askVulnFollowUp(vulnId, q)
      setThread(next)
      setQuestion('')
    } catch (err) {
      setError(displayError(err))
    } finally {
      setSubmitting(false)
    }
  }

  const contextLabel = thread?.reviewer_phase_run_id ? `Reviewer run #${thread.reviewer_phase_run_id}` : 'Reviewer 上下文'
  const canAsk = Boolean(thread?.reviewer_context_available) && !submitting

  return (
    <Card className="border border-border/60 bg-muted/20">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-medium">报告追问</div>
            <div className="text-xs text-muted-foreground">追问会接续该漏洞对应的 Reviewer 轮次上下文。</div>
          </div>
          <Badge variant={thread?.reviewer_context_available ? 'info' : 'outline'}>
            {loading ? '加载中' : thread?.reviewer_context_available ? contextLabel : '暂无上下文'}
          </Badge>
        </div>

        {!loading && !thread?.reviewer_context_available ? (
          <div className="rounded border border-border/60 bg-background/40 px-3 py-2 text-sm text-muted-foreground">
            暂无可追问的 Reviewer 上下文。新审核轮次完成后，系统会自动归档上下文并开放追问。
          </div>
        ) : null}

        {thread?.messages.length ? (
          <div className="space-y-3">
            {thread.messages.map((msg) => (
              <div
                key={msg.id}
                className={msg.role === 'user' ? 'rounded-lg bg-primary/10 p-3' : 'rounded-lg bg-background/60 p-3'}
              >
                <div className="mb-2 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>{msg.role === 'user' ? '追问' : 'Reviewer 答复'}</span>
                  <span>{formatDateTime(msg.created_at)}</span>
                </div>
                {msg.role === 'assistant' ? (
                  <Suspense fallback={<div className="text-sm text-muted-foreground">加载答复…</div>}>
                    <MarkdownView content={msg.content} />
                  </Suspense>
                ) : (
                  <div className="whitespace-pre-wrap text-sm">{msg.content}</div>
                )}
              </div>
            ))}
          </div>
        ) : null}

        <div className="space-y-2">
          <Textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="例如：这个漏洞的根因和可利用前提分别是什么？"
            disabled={!canAsk}
            className="min-h-24"
          />
          {error ? <div className="text-sm text-destructive">{error}</div> : null}
          <div className="flex justify-end">
            <Button onClick={submit} disabled={!canAsk || !question.trim()}>
              {submitting ? '追问中…' : '发送追问'}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
