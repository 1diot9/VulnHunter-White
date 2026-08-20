import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import { api } from '../api'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const links = [
  { to: '/', label: '审计项目' },
  { to: '/vulns', label: '漏洞产出' },
  { to: '/verifier-consent', label: '验证确认' },
  { to: '/containers', label: '容器管理' },
  { to: '/settings', label: '设置' },
]

export default function AppLayout() {
  const [consentCount, setConsentCount] = useState(0)

  useEffect(
    () =>
      startVisibilityPoll(() => {
        api
          .verifierConsentCount()
          .then((r) => setConsentCount(Number(r.count) || 0))
          .catch(() => {})
      }, 5000),
    [],
  )

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 shrink-0 border-b border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-4 py-3">
          <Link to="/" className="text-lg font-semibold tracking-tight">
            VulnHunter
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
                </span>
              </NavLink>
            ))}
          </nav>
        </div>
        <Separator />
      </header>
      <main className="mx-auto w-full max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
