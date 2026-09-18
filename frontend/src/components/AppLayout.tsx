import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n'
import LanguageSwitcher from '@/i18n/LanguageSwitcher'
import { api } from '../api'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { useAuth } from './AuthGate'
import { AppUpdateBanner } from './AppUpdatePanel'
import BrandLogo from './BrandLogo'
import RepoGithubLink from './RepoGithubLink'
import AppFooter from './AppFooter'

export default function AppLayout() {
  const [consentCount, setConsentCount] = useState(0)
  const [updateAvailable, setUpdateAvailable] = useState(false)
  const [updateVersion, setUpdateVersion] = useState('')
  const [updateSha, setUpdateSha] = useState('')
  const { required, lock } = useAuth()
  const { t } = useI18n()
  const links = [
    { to: '/', label: t('nav.projects') },
    { to: '/discover', label: t('nav.discover') },
    { to: '/vulns', label: t('nav.vulns') },
    { to: '/verifier-consent', label: t('nav.consent') },
    { to: '/containers', label: t('nav.containers') },
    { to: '/settings', label: t('nav.settings') },
  ]

  useEffect(
    () =>
      startVisibilityPoll(() => {
        return api
          .verifierConsentCount()
          .then((r) => setConsentCount(Number(r.count) || 0))
          .catch(() => {})
      }, 10000),
    [],
  )

  useEffect(
    () =>
      startVisibilityPoll(() => {
        return api
          .getAppUpdate()
          .then((s) => {
            setUpdateAvailable(!!s.update_available)
            setUpdateVersion(s.remote_version || '')
            setUpdateSha(s.remote_sha_short || '')
          })
          .catch(() => {})
      }, 20000),
    [],
  )

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 shrink-0 border-b border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <Link to="/" className="shrink-0 text-lg font-semibold tracking-tight">
            <BrandLogo />
          </Link>
          <nav className="flex gap-1">
            {links.map((l) => (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'rounded-md px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground',
                    isActive && 'bg-muted font-medium text-foreground',
                  )
                }
              >
                <span className="inline-flex items-center gap-1.5">
                  {l.label}
                  {l.to === '/verifier-consent' && consentCount > 0 ? (
                    <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-medium text-amber-200">
                      {consentCount > 99 ? '99+' : consentCount}
                    </span>
                  ) : null}
                  {l.to === '/settings' && updateAvailable ? (
                    <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-medium text-amber-200">
                      {t('nav.updateBadge')}
                    </span>
                  ) : null}
                </span>
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <LanguageSwitcher />
            <RepoGithubLink />
            {required ? (
              <Button type="button" variant="ghost" size="sm" onClick={lock}>
                {t('nav.logout')}
              </Button>
            ) : null}
          </div>
        </div>
        <AppUpdateBanner available={updateAvailable} version={updateVersion} sha={updateSha} />
        <Separator />
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Outlet />
      </main>
      <AppFooter />
    </div>
  )
}
