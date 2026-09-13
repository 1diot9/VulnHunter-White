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
  onRunningChange?: (running: boolean) => void
}

function isUnconstrainedPhase(logPhase: string) {
  return logPhase === 'unconstrained' || logPhase === 'unconstrained-worker'
}

function isMiningPhase(logPhase: string) {
  return (
    logPhase === 'mine' ||
    logPhase === 'worker' ||
    logPhase === 'fast' ||
    logPhase === 'fast-worker' ||
    logPhase === 'bypass' ||
    logPhase === 'bypass-worker' ||
    isUnconstrainedPhase(logPhase)
  )
}

function miningPathLabel(logPhase: string) {
  if (logPhase === 'fast' || logPhase === 'fast-worker') return '快速扫描'
  if (logPhase === 'bypass' || logPhase === 'bypass-worker') return '历史漏洞绕过'
  if (isUnconstrainedPhase(logPhase)) return '无约束扫描'
  return '启发式挖掘'
}

export function ConversationComposer({
  projectId,
  logPhase,
  session,
  sessionCount,
  projectStatus,
  onSent,
  onRunningChange,
}: ConversationComposerProps) {
  const [state, setState] = useState<ConversationState | null>(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmNew, setConfirmNew] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)

  const blocked = ['cancelled', 'ingesting', 'error'].includes(projectStatus)
  const viewingHistory = session < sessionCount
  const unconstrained = isUnconstrainedPhase(logPhase)
  const mining = isMiningPhase(logPhase)
  const pathLabel = miningPathLabel(logPhase)

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

  useEffect(() => {
    if (state == null) return
    onRunningChange?.(Boolean(state.running))
  }, [state, onRunningChange])

  useEffect(() => {
    return () => onRunningChange?.(false)
  }, [onRunningChange])

  async function submit(action: 'steer' | 'continue' | 'new' | 'stop' | 'start') {
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
      setConfirmStop(false)
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
  const canStop = Boolean(state?.can_stop)
  const canStart = Boolean(state?.can_start)
  const unconstrainedDone = Boolean(state?.unconstrained_done)
  const pathStopped = Boolean(state?.path_stopped) || (unconstrained && unconstrainedDone)

  let placeholder = '可选：接续或新开时附带说明…'
  if (mining && pathStopped) {
    placeholder = unconstrained ? '路径已停止。点启动后继续挖掘。' : `路径已暂停。点恢复或全部续跑后继续${pathLabel}。`
  } else if (running) {
    placeholder = '输入引导，将在下一轮模型调用前注入（类似 Cursor 跟进）…'
  } else if (unconstrained) {
    placeholder = '可选：接续时附带说明…'
  }

  let hint = running ? '进行中 · Ctrl+Enter 发送引导' : '空闲 · 接续保留上下文，新开放弃检查点'
  if (unconstrained) {
    if (pathStopped) hint = '已停止 · 启动或全部续跑后继续无约束扫描'
    else if (running) hint = '进行中 · Ctrl+Enter 发送引导；停止后不再新开本路径'
    else hint = '空闲 · 接续保留上下文；停止后若其他阶段已结束则项目完成'
  } else if (mining) {
    if (pathStopped) hint = `已暂停 · 恢复或全部续跑后继续${pathLabel}`
    else if (running) hint = '进行中 · Ctrl+Enter 发送引导；暂停后不再新开本路径'
    else hint = '空闲 · 接续保留上下文；暂停后若其他阶段已结束则项目完成'
  }

  const stopLabel = unconstrained ? '停止' : '暂停'
  const startLabel = unconstrained ? '启动' : '恢复'

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
        placeholder={placeholder}
        rows={3}
        disabled={busy || blocked || pathStopped}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault()
            if (running && canSteer) void submit('steer')
          }
        }}
      />
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      <div className="flex flex-wrap items-center gap-2">
        {unconstrained ? (
          running ? (
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canSteer || !message.trim()}
              onClick={() => void submit('steer')}
            >
              {busy ? '发送中…' : '发送引导'}
            </Button>
          ) : (
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canContinue}
              onClick={() => void submit('continue')}
            >
              {busy ? '处理中…' : '接续'}
            </Button>
          )
        ) : running ? (
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
        <span className="text-[11px] text-muted-foreground">{hint}</span>
      </div>
      {mining ? (
        <div className="flex flex-wrap items-center gap-2">
          {canStart ? (
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canStart}
              onClick={() => void submit('start')}
            >
              {busy ? `${startLabel}中…` : startLabel}
            </Button>
          ) : (
            <Button
              type="button"
              size="sm"
              variant="warning"
              disabled={busy || blocked || !canStop}
              onClick={() => setConfirmStop(true)}
            >
              {stopLabel}
            </Button>
          )}
        </div>
      ) : null}

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

      <Dialog open={confirmStop} onOpenChange={(o) => !busy && setConfirmStop(o)}>
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{unconstrained ? '停止无约束扫描？' : `暂停${pathLabel}？`}</DialogTitle>
            <DialogDescription>
              {unconstrained
                ? '将结束当前挖掘轮并停止本路径。若其他挖掘与审核均已结束，项目将标记为完成。之后可再点启动或全部续跑继续挖。'
                : `将结束当前挖掘轮并暂停${pathLabel}。若其他挖掘与审核均已结束，项目将标记为完成。之后可再点恢复或全部续跑继续挖。`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setConfirmStop(false)}>
              取消
            </Button>
            <Button type="button" variant="warning" disabled={busy} onClick={() => void submit('stop')}>
              {busy ? (unconstrained ? '停止中…' : '暂停中…') : unconstrained ? '确认停止' : '确认暂停'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
