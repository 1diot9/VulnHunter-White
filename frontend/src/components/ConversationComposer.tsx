import { useCallback, useEffect, useState } from 'react'
import { api, formatApiError, type ConversationState } from '../api'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n'
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

function isAttackChainPhase(logPhase: string) {
  return logPhase === 'attack_chain' || logPhase === 'attack-chain'
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

function miningPathLabel(logPhase: string, t: (k: string) => string) {
  if (isAttackChainPhase(logPhase)) return t('flow.composer.path.chain')
  if (logPhase === 'fast' || logPhase === 'fast-worker') return t('mining.fast')
  if (logPhase === 'bypass' || logPhase === 'bypass-worker') return t('mining.bypass')
  if (isUnconstrainedPhase(logPhase)) return t('mining.unconstrained')
  return t('mining.heuristic')
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
  const { t } = useI18n()
  const [state, setState] = useState<ConversationState | null>(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmNew, setConfirmNew] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)

  const blocked = ['cancelled', 'ingesting', 'error'].includes(projectStatus)
  const viewingHistory = session < sessionCount
  const unconstrained = isUnconstrainedPhase(logPhase)
  const attackChain = isAttackChainPhase(logPhase)
  const mining = isMiningPhase(logPhase)
  const pathControls = mining || attackChain
  const pathLabel = miningPathLabel(logPhase, t)

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
      setError(t('flow.composer.needSteer'))
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

  let placeholder = t('flow.composer.ph.optional')
  if (pathControls && pathStopped) {
    placeholder = unconstrained ? t('flow.composer.ph.stopped') : t('flow.composer.ph.paused', { path: pathLabel })
  } else if (running) {
    placeholder = t('flow.composer.ph.steer')
  } else if (unconstrained) {
    placeholder = t('flow.composer.ph.continue')
  }

  let hint = running ? t('flow.composer.hint.run') : t('flow.composer.hint.idle')
  if (unconstrained) {
    if (pathStopped) hint = t('flow.composer.hint.uStopped')
    else if (running) hint = t('flow.composer.hint.uRun')
    else hint = t('flow.composer.hint.uIdle')
  } else if (pathControls) {
    if (pathStopped) hint = t('flow.composer.hint.pStopped', { path: pathLabel })
    else if (running) hint = attackChain ? t('flow.composer.hint.pRunPhase') : t('flow.composer.hint.pRunPath')
    else hint = t('flow.composer.hint.pIdle')
  }

  const stopLabel = unconstrained ? t('flow.composer.stop') : t('flow.composer.pause')
  const startLabel = unconstrained ? t('flow.composer.start') : t('flow.composer.resume')

  return (
    <div className="mt-3 space-y-2 border-t border-border pt-3">
      {viewingHistory ? (
        <p className="text-xs text-muted-foreground">{t('flow.composer.historyNote')}</p>
      ) : null}
      {blocked ? (
        <p className="text-xs text-muted-foreground">{t('flow.composer.blocked')}</p>
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
              {busy ? t('flow.composer.sending') : t('flow.composer.sendSteer')}
            </Button>
          ) : (
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canContinue}
              onClick={() => void submit('continue')}
            >
              {busy ? t('flow.composer.processing') : t('flow.composer.continue')}
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
              {busy ? t('flow.composer.sending') : t('flow.composer.sendSteer')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || blocked || !canNew}
              onClick={() => setConfirmNew(true)}
            >
              {t('flow.composer.new')}
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
              {busy ? t('flow.composer.processing') : t('flow.composer.continue')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || blocked || !canNew}
              onClick={() => void submit('new')}
            >
              {t('flow.composer.new')}
            </Button>
          </>
        )}
        <span className="text-[11px] text-muted-foreground">{hint}</span>
      </div>
      {pathControls ? (
        <div className="flex flex-wrap items-center gap-2">
          {canStart ? (
            <Button
              type="button"
              size="sm"
              disabled={busy || blocked || !canStart}
              onClick={() => void submit('start')}
            >
              {busy ? t('flow.composer.startingNamed', { label: startLabel }) : startLabel}
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
            <DialogTitle>{t('flow.composer.newTitle')}</DialogTitle>
            <DialogDescription>
              {t('flow.composer.newBody')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setConfirmNew(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="button" disabled={busy} onClick={() => void submit('new')}>
              {busy ? t('flow.composer.launching') : t('flow.composer.confirmNew')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmStop} onOpenChange={(o) => !busy && setConfirmStop(o)}>
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{unconstrained ? t('flow.composer.stopUnconst') : t('flow.composer.pausePath', { path: pathLabel })}</DialogTitle>
            <DialogDescription>
              {unconstrained
                ? t('flow.composer.stopUnconstBody')
                : attackChain
                  ? t('flow.composer.pauseChainBody')
                  : t('flow.composer.pausePathBody', { path: pathLabel })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={() => setConfirmStop(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="button" variant="warning" disabled={busy} onClick={() => void submit('stop')}>
              {busy ? (unconstrained ? t('flow.composer.stopping') : t('flow.composer.pausing')) : unconstrained ? t('flow.composer.confirmStop') : t('flow.composer.confirmPause')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
