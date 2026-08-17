import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Loader2Icon } from 'lucide-react'
import { api, type VulnFollowUpMessage, type VulnFollowUpThread } from '../api'
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
  const thinkingRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    let alive = true
    setThread(null)
    setError('')
    setQuestion('')
    setSubmitting(false)
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

  useEffect(() => {
    if (!submitting) return
    thinkingRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [submitting])

  async function submit() {
    const q = question.trim()
    if (!q || submitting || !thread?.reviewer_context_available) return
    const pending: VulnFollowUpMessage = {
      id: `pending-${Date.now()}`,
      role: 'user',
      content: q,
      created_at: new Date().toISOString(),
      reviewer_phase_run_id: thread.reviewer_phase_run_id,
    }
    setSubmitting(true)
    setError('')
    setQuestion('')
    setThread({ ...thread, messages: [...thread.messages, pending] })
    try {
      const next = await api.askVulnFollowUp(vulnId, q)
      setThread(next)
    } catch (err) {
      setThread((cur) =>
        cur ? { ...cur, messages: cur.messages.filter((msg) => msg.id !== pending.id) } : cur,
      )
      setQuestion(q)
      setError(displayError(err))
    } finally {
      setSubmitting(false)
    }
  }

  const contextLabel = thread?.reviewer_phase_run_id ? `Reviewer run #${thread.reviewer_phase_run_id}` : 'Reviewer 上下文'
  const canAsk = Boolean(thread?.reviewer_context_available) && !submitting
  const visibleMessages = thread?.messages ?? []

  return (
    <Card className="border border-border/60 bg-muted/20">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-medium">报告追问</div>
            <div className="text-xs text-muted-foreground">
              追问会接续该漏洞对应的 Reviewer 轮次上下文，后续追问会带上此前问答。
            </div>
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

        {visibleMessages.length || submitting ? (
          <div className="space-y-3">
            {visibleMessages.map((msg) => (
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
            {submitting ? (
              <div
                ref={thinkingRef}
                className="rounded-lg border border-border/60 bg-background/60 p-3"
                aria-live="polite"
                aria-busy="true"
              >
                <div className="mb-3 flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2Icon className="size-4 animate-spin" />
                  <span>模型思考中…</span>
                </div>
                <div className="space-y-2">
                  <div className="h-2.5 w-[88%] animate-pulse rounded bg-muted" />
                  <div className="h-2.5 w-[64%] animate-pulse rounded bg-muted" />
                  <div className="h-2.5 w-[76%] animate-pulse rounded bg-muted" />
                </div>
              </div>
            ) : null}
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
            <Button onClick={() => void submit()} disabled={!canAsk || !question.trim()}>
              {submitting ? (
                <>
                  <Loader2Icon className="animate-spin" />
                  追问中…
                </>
              ) : (
                '发送追问'
              )}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
