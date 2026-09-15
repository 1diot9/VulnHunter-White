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
import { useI18n } from '@/i18n'

type SubId = 'map' | 'old_vulns'

function subMeta(t: (key: string) => string): Record<SubId, { title: string; description: string; confirm: string }> {
  return {
    map: {
      title: t('flow.recon.mapTitle'),
      description: t('flow.recon.mapBody'),
      confirm: t('flow.recon.startUpdate'),
    },
    old_vulns: {
      title: t('flow.recon.oldTitle'),
      description: t('flow.recon.oldBody'),
      confirm: t('flow.recon.startUpdate'),
    },
  }
}

type ReconDocRerunButtonsProps = {
  project: Project
  onStarted?: (subId: SubId) => void
}

export function ReconDocRerunButtons({ project, onStarted }: ReconDocRerunButtonsProps) {
  const { t } = useI18n()
  const [pending, setPending] = useState<SubId | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const mapDone = Boolean(project.recon_subphases?.find((s) => s.id === 'map')?.done)
  const oldDone = Boolean(project.recon_subphases?.find((s) => s.id === 'old_vulns')?.done)
  if (!mapDone && !oldDone) return null

  const meta = pending ? subMeta(t)[pending] : null

  const close = () => {
    if (busy) return
    setPending(null)
    setError('')
  }

  async function confirm() {
    if (!pending || busy) return
    const sub = pending
    setBusy(true)
    setError('')
    try {
      await api.rerunReconSubphase(project.id, sub)
      setPending(null)
      onStarted?.(sub)
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="inline-flex flex-wrap items-center gap-1.5 rounded-lg border border-dashed border-slate-600/80 bg-slate-900/40 px-1.5 py-1">
        <span className="px-1 text-[11px] text-slate-500">{t('flow.recon.group')}</span>
        {mapDone ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 text-slate-300"
            disabled={busy}
            title={t('flow.recon.mapTip')}
            onClick={() => {
              setError('')
              setPending('map')
            }}
          >
            {t('flow.recon.mapBtn')}
          </Button>
        ) : null}
        {oldDone ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 text-slate-300"
            disabled={busy}
            title={t('flow.recon.oldTip')}
            onClick={() => {
              setError('')
              setPending('old_vulns')
            }}
          >
            {t('flow.recon.oldBtn')}
          </Button>
        ) : null}
      </div>
      <Dialog
        open={pending != null}
        onOpenChange={(next) => {
          if (!next) close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{meta?.title}</DialogTitle>
            <DialogDescription className="whitespace-pre-wrap leading-relaxed">
              {meta?.description}
            </DialogDescription>
          </DialogHeader>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              {t('common.cancel')}
            </Button>
            <Button type="button" disabled={busy} onClick={() => void confirm()}>
              {busy ? t('flow.composer.launching') : meta?.confirm ?? t('common.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
