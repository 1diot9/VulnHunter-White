import { useState } from 'react'
import { api, formatApiError, type Project } from '../api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'

const RESET_OK_STATUSES = new Set(['paused', 'completed', 'cancelled', 'error'])

type ResetProgressButtonProps = {
  project: Project
  onReset?: (project: Project) => void
}

export function ResetProgressButton({ project, onReset }: ResetProgressButtonProps) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [acked, setAcked] = useState(false)
  const [error, setError] = useState('')
  const allowed = RESET_OK_STATUSES.has(project.status)

  const close = () => {
    if (busy) return
    setOpen(false)
    setAcked(false)
    setError('')
  }

  function openDialog() {
    if (!allowed) return
    setError('')
    setAcked(false)
    setOpen(true)
  }

  async function confirmReset() {
    if (!acked || busy) return
    setBusy(true)
    setError('')
    try {
      const next = await api.resetProgress(project.id)
      setOpen(false)
      setAcked(false)
      onReset?.(next)
    } catch (e) {
      setError(formatApiError(e, t('comp.reset.timeout')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="warning"
        disabled={!allowed}
        title={allowed ? t('comp.reset.tipOk') : t('comp.reset.tipNeedPause')}
        onClick={openDialog}
      >
        {t('comp.reset.btn')}
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (next) openDialog()
          else close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{t('comp.reset.title')}</DialogTitle>
            <DialogDescription>{t('comp.reset.body', { name: project.name })}</DialogDescription>
          </DialogHeader>
          <Label className="items-start font-normal">
            <Checkbox
              className="mt-0.5"
              checked={acked}
              disabled={busy}
              onCheckedChange={(checked) => setAcked(checked === true)}
            />
            <span className="min-w-0 text-sm leading-relaxed">{t('comp.reset.ack')}</span>
          </Label>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button
              type="button"
              variant="warning"
              disabled={busy || !acked}
              onClick={() => void confirmReset()}
            >
              {busy ? t('comp.reset.resetting') : t('comp.reset.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
