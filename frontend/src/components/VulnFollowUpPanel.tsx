import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Loader2Icon } from 'lucide-react'
import { api, formatApiError, type VulnFollowUpMessage, type VulnFollowUpThread, type VulnReportKind, type VulnReportRevision } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { formatDateTime } from '../lib/utils'
import { useI18n } from '@/i18n'
import { t as translate } from '@/i18n/t'

const MarkdownView = lazy(() => import('./MarkdownView'))

function displayError(err: unknown) {
  return formatApiError(err, translate('comp.follow.timeout'))
}

function reportKindLabel(kind: VulnReportKind): string {
  if (kind === 'report') return translate('comp.follow.kind.report')
  if (kind === 'advisory') return 'Advisory'
  return 'CVE JSON'
}

export default function VulnFollowUpPanel({
  vulnId,
  onReportApplied,
}: {
  vulnId: number
  onReportApplied?: () => void | Promise<void>
}) {
  const { t } = useI18n()
  const [thread, setThread] = useState<VulnFollowUpThread | null>(null)
  const [mode, setMode] = useState<'ask' | 'revise'>('ask')
  const [question, setQuestion] = useState('')
  const [revisionKind, setRevisionKind] = useState<VulnReportKind>('report')
  const [revisionDraft, setRevisionDraft] = useState<VulnReportRevision | null>(null)
  const [revisionContent, setRevisionContent] = useState('')
  const [applying, setApplying] = useState(false)
  const [appliedMessage, setAppliedMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const thinkingRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    let alive = true
    setThread(null)
    setError('')
    setQuestion('')
    setMode('ask')
    setRevisionKind('report')
    setRevisionDraft(null)
    setRevisionContent('')
    setAppliedMessage('')
    setSubmitting(false)
    setApplying(false)
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

  async function reloadThread() {
    try {
      setThread(await api.listVulnFollowUps(vulnId))
    } catch {
      /* keep current thread */
    }
  }

  async function generateRevision() {
    const instruction = question.trim()
    if (!instruction || submitting || applying || loading) return
    setSubmitting(true)
    setError('')
    setAppliedMessage('')
    setRevisionDraft(null)
    setRevisionContent('')
    try {
      const draft = await api.generateVulnReportRevision(vulnId, revisionKind, instruction)
      setRevisionDraft(draft)
      setRevisionContent(draft.revised_text)
      setQuestion('')
      await reloadThread()
    } catch (err) {
      setError(displayError(err))
    } finally {
      setSubmitting(false)
    }
  }

  async function applyRevision() {
    if (!revisionDraft || !revisionContent.trim() || applying || submitting) return
    setApplying(true)
    setError('')
    setAppliedMessage('')
    try {
      const result = await api.applyVulnReportRevision(
        vulnId,
        revisionDraft.kind,
        revisionContent,
        revisionDraft.summary,
      )
      setAppliedMessage(result.message || t('comp.follow.applied'))
      setRevisionDraft(null)
      setRevisionContent('')
      await reloadThread()
      await onReportApplied?.()
    } catch (err) {
      setError(displayError(err))
    } finally {
      setApplying(false)
    }
  }

  const contextLabel = thread?.reviewer_phase_run_id ? `Reviewer run #${thread.reviewer_phase_run_id}` : t('comp.follow.reviewerCtx')
  const canAsk = Boolean(thread?.reviewer_context_available) && !submitting
  const canRevise = !loading && !submitting && !applying
  const visibleMessages = thread?.messages ?? []

  return (
    <Card className="border border-border/60 bg-muted/20">
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="font-medium">{t('comp.follow.title')}</div>
            <div className="text-xs text-muted-foreground">
              {t('comp.follow.body')}
            </div>
          </div>
          <Badge variant={thread?.reviewer_context_available ? 'info' : 'outline'}>
            {loading ? t('comp.follow.loading') : thread?.reviewer_context_available ? contextLabel : t('comp.follow.noCtx')}
          </Badge>
        </div>

        {!loading && !thread?.reviewer_context_available ? (
          <div className="rounded border border-border/60 bg-background/40 px-3 py-2 text-sm text-muted-foreground">
            {t('comp.follow.noAsk')}
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
                  <span>{msg.role === 'user' ? t('comp.follow.ask') : t('comp.follow.reply')}</span>
                  <span>{formatDateTime(msg.created_at)}</span>
                </div>
                {msg.role === 'assistant' ? (
                  <Suspense fallback={<div className="text-sm text-muted-foreground">{t('comp.follow.loadReply')}</div>}>
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
                  <span>{t('comp.follow.thinking')}</span>
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
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant={mode === 'ask' ? 'default' : 'outline'} onClick={() => setMode('ask')}>
              {t('comp.follow.askReport')}
            </Button>
            <Button size="sm" variant={mode === 'revise' ? 'default' : 'outline'} onClick={() => setMode('revise')}>
              {t('comp.follow.editReport')}
            </Button>
          </div>
          {mode === 'revise' ? (
            <div className="flex flex-wrap gap-2">
              {(['report', 'advisory', 'cve'] as VulnReportKind[]).map((kind) => (
                <Button
                  key={kind}
                  size="sm"
                  variant={revisionKind === kind ? 'default' : 'outline'}
                  onClick={() => {
                    setRevisionKind(kind)
                    setRevisionDraft(null)
                    setRevisionContent('')
                    setAppliedMessage('')
                  }}
                >
                  {reportKindLabel(kind)}
                </Button>
              ))}
            </div>
          ) : null}
          <Textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder={
              mode === 'ask'
                ? t('comp.follow.phAsk')
                : revisionKind === 'advisory'
                  ? t('comp.follow.phAdv')
                  : revisionKind === 'cve'
                    ? t('comp.follow.phCve')
                    : t('comp.follow.phZh')
            }
            disabled={mode === 'ask' ? !canAsk : !canRevise}
            className="min-h-24"
          />
          {error ? <div className="text-sm text-destructive">{error}</div> : null}
          {appliedMessage ? <div className="text-sm text-emerald-300">{appliedMessage}</div> : null}
          {mode === 'revise' && revisionDraft ? (
            <div className="space-y-2 rounded border border-border/60 bg-background/50 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <div className="text-sm font-medium">{t('comp.follow.preview', { kind: reportKindLabel(revisionDraft.kind) })}</div>
                  <div className="text-xs text-muted-foreground">
                    {revisionDraft.summary || t('comp.follow.check')}
                  </div>
                </div>
                <Badge variant={revisionDraft.reviewer_context_available ? 'info' : 'outline'}>
                  {revisionDraft.reviewer_context_available ? t('comp.follow.withCtx') : t('comp.follow.reportOnly')}
                </Badge>
              </div>
              <Textarea
                value={revisionContent}
                onChange={(e) => setRevisionContent(e.target.value)}
                className="min-h-72 font-mono text-xs"
              />
              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  variant="outline"
                  disabled={applying}
                  onClick={() => {
                    setRevisionDraft(null)
                    setRevisionContent('')
                  }}
                >
                  {t('comp.follow.discard')}
                </Button>
                <Button onClick={() => void applyRevision()} disabled={applying || !revisionContent.trim()}>
                  {applying ? (
                    <>
                      <Loader2Icon className="animate-spin" />
                      {t('comp.follow.applying')}
                    </>
                  ) : (
                    t('comp.follow.apply')
                  )}
                </Button>
              </div>
            </div>
          ) : null}
          <div className="flex justify-end">
            {mode === 'ask' ? (
              <Button onClick={() => void submit()} disabled={!canAsk || !question.trim()}>
                {submitting ? (
                  <>
                    <Loader2Icon className="animate-spin" />
                    {t('comp.follow.asking')}
                  </>
                ) : (
                  t('comp.follow.sendAsk')
                )}
              </Button>
            ) : (
              <Button onClick={() => void generateRevision()} disabled={!canRevise || !question.trim()}>
                {submitting ? (
                  <>
                    <Loader2Icon className="animate-spin" />
                    {t('comp.follow.generating')}
                  </>
                ) : (
                  t('comp.follow.generate')
                )}
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
