import { useCallback, useEffect, useState } from 'react'
import { api, formatApiError, type ConversationState } from '../api'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

type ConversationComposerProps = {
  projectId: number
  logPhase: string
  session: number
  sessionCount: number
  projectStatus: string
  onSent?: () => void
}

export function ConversationComposer({
  projectId,
  logPhase,
  session,
  sessionCount,
  projectStatus,
  onSent,
}: ConversationComposerProps) {
  const [state, setState] = useState<ConversationState | null>(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmNew, setConfirmNew] = useState(false)

  const blocked = ['cancelled', 'ingesting', 'error'].includes(projectStatus)
  const viewingHistory = session < sessionCount

  const refresh = useCallback(async () => {
    try {
      const s = await api.getConversationState(projectId, logPhase)
      setState(s)
    } catch {
      setState(null)
    }
  }, [projectId, logPhase])

  useEffect(() => {
    void refresh()
    const t = window.setInterval(() => void refresh(), 4000)
    return () => window.clearInterval(t)
  }, [refresh])

  async function submit(action: 'steer' | 'continue' | 'new') {
    if (busy || blocked) return
    if (action === 'steer' && !message.trim()) {
      setError('请输入引导内容')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.postConversation(projectId, {
        log_phase: logPhase,
        action,
        message: message.trim(),
      })
      setMessage('')
      setConfirmNew(false)
      await refresh()
      onSent?.()
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  const running = Boolean(state?.running)
  const canContinue = Boolean(state?.can_continue)
  const canNew = Boolean(state?.can_new)
  const canSteer = Boolean(state?.can_steer)

  return (
    <div className="mt-3 space-y-2 border-t border-border pt-3">
      {viewingHistory ? (
        <p className="text-xs text-muted-foreground">正在查看历史轮次；输入将作用于该小阶段最新一轮。</p>
      ) : null}
      {blocked ? (
        <p className="text-xs text-muted-foreground">当前项目状态不可操作对话。</p>
      ) : null}
      <Textarea
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder={
          running
            ? '输入引导，将在下一轮模型调用前注入（类似 Cursor 跟进）…'
            : '可选：接续或新开时附带说明…'
        }
        rows={3}
        disabled={busy || blocked}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault()
            if (running && canSteer) void submit('steer')
          }
        }}
      />
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      <div className="flex flex-wrap items-center gap-2">
        {running ? (
          <>
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canSteer || !message.trim()}
              onClick={() => void submit('steer')}
            >
              {busy ? '发送中…' : '发送引导'}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || blocked || !canNew}
              onClick={() => setConfirmNew(true)}
            >
              新开
            </Button>
          </>
        ) : (
          <>
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canContinue}
              onClick={() => void submit('continue')}
            >
              {busy ? '处理中…' : '接续'}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || blocked || !canNew}
              onClick={() => void submit('new')}
            >
              新开
            </Button>
          </>
        )}
        <span className="text-[11px] text-muted-foreground">
          {running ? '进行中 · Ctrl+Enter 发送引导' : '空闲 · 接续保留上下文，新开放弃检查点'}
        </span>
      </div>

      <Dialog open={confirmNew} onOpenChange={(o) => !busy && setConfirmNew(o)}>
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>新开一轮对话？</DialogTitle>
            <DialogDescription>
              将打断当前进行中的对话、放弃可恢复检查点，并按你填写的说明新开一轮。此操作不可撤销。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setConfirmNew(false)}>
              取消
            </Button>
            <Button type="button" disabled={busy} onClick={() => void submit('new')}>
              {busy ? '启动中…' : '确认新开'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
