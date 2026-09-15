import { useState } from 'react'
import { api, formatApiError, type Project } from '../api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n'

type LabSetupRetryButtonProps = {
  project: Project
  onStarted?: () => void
}

export function LabSetupRetryButton({ project, onStarted }: LabSetupRetryButtonProps) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [userMessage, setUserMessage] = useState('')

  if (!project.lab_setup_retryable) return null

  const close = () => {
    if (busy) return
    setOpen(false)
    setError('')
    setUserMessage('')
  }

  async function confirm() {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await api.retryLabSetup(project.id, userMessage.trim())
      setOpen(false)
      setUserMessage('')
      onStarted?.()
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        title={t('flow.labRetry.tip')}
        onClick={() => {
          setError('')
          setOpen(true)
        }}
      >
        {t('flow.labRetry.btn')}
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{t('flow.labRetry.title')}</DialogTitle>
            <DialogDescription className="whitespace-pre-wrap leading-relaxed">
              {t('flow.labRetry.body')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <label className="text-sm text-muted-foreground" htmlFor="lab-retry-message">
              {t('flow.labRetry.note')}
            </label>
            <Textarea
              id="lab-retry-message"
              value={userMessage}
              onChange={(e) => setUserMessage(e.target.value)}
              placeholder={t('flow.labRetry.placeholder')}
              rows={4}
              disabled={busy}
            />
          </div>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button type="button" disabled={busy} onClick={() => void confirm()}>
              {busy ? t('flow.composer.launching') : t('flow.labRetry.start')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
