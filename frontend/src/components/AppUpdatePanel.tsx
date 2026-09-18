import { useEffect, useState, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { api, formatApiError, isTimeoutError, type AppUpdateStatus } from '../api'
import { useI18n } from '@/i18n'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

function formatCheckedAt(iso: string | null, fallback: string): string {
  if (!iso) return fallback
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString()
}

function versionLabel(
  t: (key: string, vars?: Record<string, string | number>) => string,
  version: string,
  sha: string,
  kind: 'current' | 'remote',
): string {
  const short = sha || '—'
  if (version) return t(`settings.update.${kind}`, { version, sha: short })
  return t('settings.update.shaOnly', { sha: short })
}

function reasonText(
  t: (key: string, vars?: Record<string, string | number>) => string,
  reason: string,
  extra = '',
): string {
  if (!reason && !extra) return ''
  const key = reason ? `settings.update.reason.${reason}` : ''
  const mapped = key ? t(key) : ''
  const base = mapped && mapped !== key ? mapped : extra
  if (mapped && mapped !== key && extra && extra !== mapped) return `${mapped} ${extra}`
  return base || extra || reason
}

async function waitForRestart(timeoutMs = 120_000): Promise<boolean> {
  const downDeadline = Date.now() + 25_000
  let sawDown = false
  while (Date.now() < downDeadline) {
    try {
      await api.health()
    } catch {
      sawDown = true
      break
    }
    await new Promise((resolve) => setTimeout(resolve, 400))
  }
  const upDeadline = Date.now() + timeoutMs
  let consecutiveOk = 0
  while (Date.now() < upDeadline) {
    try {
      const health = await api.health()
      if (health.ok) {
        consecutiveOk += 1
        if (consecutiveOk >= 2 && (sawDown || Date.now() >= downDeadline)) return true
      } else {
        consecutiveOk = 0
      }
    } catch {
      sawDown = true
      consecutiveOk = 0
    }
    await new Promise((resolve) => setTimeout(resolve, 1500))
  }
  return false
}

function isDisconnectError(e: unknown): boolean {
  if (isTimeoutError(e)) return true
  const text = (e instanceof Error ? e.message : String(e || '')).toLowerCase()
  return (
    text.includes('failed to fetch') ||
    text.includes('network') ||
    text.includes('load failed') ||
    text.includes('econnreset') ||
    text.includes('connection')
  )
}

export function AppUpdateBanner({ available, version, sha }: { available: boolean; version: string; sha: string }) {
  const { t } = useI18n()
  const location = useLocation()
  if (!available || location.pathname === '/settings') return null
  const text = version
    ? t('settings.update.banner', { version })
    : t('settings.update.bannerSha', { sha: sha || '…' })
  return (
    <div className="border-b border-amber-500/30 bg-amber-500/10">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 px-4 py-2 text-sm text-amber-100">
        <span>{text}</span>
        <Link
          to="/settings#app-update"
          className="inline-flex h-7 items-center rounded-lg bg-amber-500/20 px-2.5 text-xs font-medium text-amber-50 hover:bg-amber-500/30"
        >
          {t('settings.update.bannerAction')}
        </Link>
      </div>
    </div>
  )
}

export function AppUpdateCard() {
  const { t } = useI18n()
  const [status, setStatus] = useState<AppUpdateStatus | null>(null)
  const [checking, setChecking] = useState(false)
  const [applying, setApplying] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [msg, setMsg] = useState('')
  const [ok, setOk] = useState<boolean | null>(null)

  useEffect(() => {
    if (window.location.hash === '#app-update') {
      document.getElementById('app-update')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [])

  useEffect(
    () =>
      startVisibilityPoll(() => {
        if (applying || restarting) return
        return api
          .getAppUpdate()
          .then((next) => {
            setStatus(next)
            if (next.restarting) setRestarting(true)
          })
          .catch(() => {})
      }, 15000),
    [applying, restarting],
  )

  useEffect(() => {
    if (!restarting) return
    let cancelled = false
    void waitForRestart().then((ready) => {
      if (cancelled) return
      if (ready) {
        window.location.assign('/settings#app-update')
        window.location.reload()
        return
      }
      setRestarting(false)
      setOk(false)
      setMsg(t('settings.update.restartTimeout'))
    })
    return () => {
      cancelled = true
    }
  }, [restarting, t])

  async function checkNow() {
    setChecking(true)
    setMsg('')
    setOk(null)
    try {
      const next = await api.checkAppUpdate()
      setStatus(next)
      setOk(!next.last_error)
      if (next.last_error) setMsg(next.last_error)
    } catch (e) {
      setOk(false)
      setMsg(formatApiError(e, t('settings.update.timeout')))
    } finally {
      setChecking(false)
    }
  }

  async function applyNow() {
    setConfirmOpen(false)
    setApplying(true)
    setMsg('')
    setOk(null)
    try {
      const out = await api.applyAppUpdate()
      if (out.ok && out.restarting) {
        setRestarting(true)
        return
      }
      setOk(false)
      setMsg(reasonText(t, out.reason, out.error))
      const next = await api.getAppUpdate().catch(() => null)
      if (next) setStatus(next)
    } catch (e) {
      if (isDisconnectError(e)) {
        setRestarting(true)
        return
      }
      setOk(false)
      setMsg(formatApiError(e, t('settings.update.applyTimeout')))
    } finally {
      setApplying(false)
    }
  }

  const blocked = status
    ? reasonText(t, status.apply_blocked_reason, status.last_error)
    : ''

  return (
    <>
      <Card id="app-update">
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <LabelRow
              title={t('settings.update.title')}
              badge={
                status?.update_available ? (
                  <Badge variant="warning">{t('settings.update.available')}</Badge>
                ) : status ? (
                  <Badge variant="success">{t('settings.update.latest')}</Badge>
                ) : null
              }
            />
            <div className="text-xs text-slate-500">{t('settings.update.hint')}</div>
            {status ? (
              <div className="space-y-1 text-sm text-slate-300">
                <div>
                  {versionLabel(t, status.current_version, status.current_sha_short, 'current')}
                </div>
                {status.update_available ? (
                  <div>{versionLabel(t, status.remote_version, status.remote_sha_short, 'remote')}</div>
                ) : null}
                <div className="text-xs text-slate-500">
                  {t('settings.update.checked', {
                    time: formatCheckedAt(status.last_checked_at, t('settings.update.neverChecked')),
                  })}
                </div>
              </div>
            ) : (
              <div className="text-sm text-slate-400">{t('common.loading')}</div>
            )}
            {blocked && status && !status.can_apply && status.apply_blocked_reason !== 'no_update' ? (
              <div className="text-sm text-amber-200">{blocked}</div>
            ) : null}
            {msg ? (
              <div className={ok === false ? 'text-sm text-red-300' : 'text-sm text-slate-300'}>{msg}</div>
            ) : null}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" disabled={checking || applying || restarting} onClick={() => void checkNow()}>
                {checking ? t('settings.update.checking') : t('settings.update.check')}
              </Button>
              <Button
                type="button"
                disabled={!status?.can_apply || applying || restarting || !!status?.applying || !!status?.restarting}
                onClick={() => setConfirmOpen(true)}
              >
                {applying ? t('settings.update.applying') : t('settings.update.apply')}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
      <Dialog
        open={confirmOpen}
        onOpenChange={(next) => {
          if (applying || restarting) return
          setConfirmOpen(next)
        }}
      >
        <DialogContent showCloseButton={!applying}>
          <DialogHeader>
            <DialogTitle>{t('settings.update.confirmTitle')}</DialogTitle>
            <DialogDescription>{t('settings.update.confirmBody')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={applying} onClick={() => setConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button disabled={applying} onClick={() => void applyNow()}>
              {applying ? t('settings.update.applying') : t('settings.update.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {restarting ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
          <div className="rounded-lg border border-border bg-background px-6 py-5 text-sm text-foreground shadow-lg">
            {t('settings.update.restarting')}
          </div>
        </div>
      ) : null}
    </>
  )
}

function LabelRow({ title, badge }: { title: string; badge: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="text-sm font-medium text-slate-200">{title}</div>
      {badge}
    </div>
  )
}
