import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2Icon } from 'lucide-react'
import { api, formatApiError, type HarnessConsentItem, type VerifierConsentItem } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { formatDateTime, formatSeverity, formatSeverityScore, severityScoreBadgeClass } from '../lib/utils'
import { useI18n } from '@/i18n'
import { readJsonCache, writeJsonCache } from '../lib/listCache'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const INTERNET_CACHE_KEY = 'vh:verifier-consent'
const HARNESS_CACHE_KEY = 'vh:harness-consent'

type ConsentTab = 'internet' | 'harness'

type SharedItem = {
  id: number
  project_id: number
  project_name: string
  title: string
  vuln_type: string | null
  severity: string | null
  severity_score: number | null
  cvss_vector?: string | null
  reason: string
  updated_at: string
}

function toInternet(
  item: VerifierConsentItem,
  t: (key: string) => string,
): SharedItem {
  return {
    id: item.id,
    project_id: item.project_id,
    project_name: item.project_name,
    title: item.title,
    vuln_type: item.vuln_type,
    severity: item.severity,
    severity_score: item.severity_score,
    cvss_vector: item.cvss_vector,
    reason: item.verifier_ask_reason || t('consent.reasonInternet'),
    updated_at: item.updated_at,
  }
}

function toHarness(item: HarnessConsentItem, t: (key: string) => string): SharedItem {
  return {
    id: item.id,
    project_id: item.project_id,
    project_name: item.project_name,
    title: item.title,
    vuln_type: item.vuln_type,
    severity: item.severity,
    severity_score: item.severity_score,
    cvss_vector: item.cvss_vector,
    reason: item.harness_ask_reason || t('consent.reasonHarness'),
    updated_at: item.updated_at,
  }
}

export default function VerifierConsentPage() {
  const { t } = useI18n()
  const cachedInternet = readJsonCache<VerifierConsentItem[]>(INTERNET_CACHE_KEY)
  const cachedHarness = readJsonCache<HarnessConsentItem[]>(HARNESS_CACHE_KEY)
  const [internet, setInternet] = useState<VerifierConsentItem[]>(cachedInternet ?? [])
  const [harness, setHarness] = useState<HarnessConsentItem[]>(cachedHarness ?? [])
  const [tab, setTab] = useState<ConsentTab | null>(null)
  const [instructions, setInstructions] = useState<Record<string, string>>({})
  const [busyKey, setBusyKey] = useState<string | null>(null)
  const [error, setError] = useState('')

  const refresh = () =>
    Promise.all([api.listVerifierConsent(), api.listHarnessConsent()])
      .then(([web, local]) => {
        setInternet(web)
        setHarness(local)
        writeJsonCache(INTERNET_CACHE_KEY, web)
        writeJsonCache(HARNESS_CACHE_KEY, local)
      })
      .catch(() => {})

  useEffect(() => startVisibilityPoll(refresh, 4000), [])

  const resolvedTab: ConsentTab = useMemo(() => {
    if (tab) return tab
    if (internet.length === 0 && harness.length > 0) return 'harness'
    return 'internet'
  }, [tab, internet.length, harness.length])

  const items = resolvedTab === 'internet' ? internet.map((item) => toInternet(item, t)) : harness.map((item) => toHarness(item, t))
  const emptyHint =
    resolvedTab === 'internet' ? t('consent.emptyInternet') : t('consent.emptyHarness')

  const submit = async (id: number, action: 'skip' | 'continue') => {
    const key = `${resolvedTab}-${id}`
    setBusyKey(key)
    setError('')
    try {
      const note = instructions[key] || ''
      if (resolvedTab === 'internet') {
        await api.resolveVerifierConsent(id, action, note)
      } else {
        await api.resolveHarnessConsent(id, action, note)
      }
      setInstructions((prev) => {
        const next = { ...prev }
        delete next[key]
        return next
      })
      await refresh()
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusyKey(null)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t('nav.consent')}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t('consent.subtitle')}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          size="sm"
          variant={resolvedTab === 'internet' ? 'default' : 'outline'}
          onClick={() => setTab('internet')}
        >
          {t('consent.internet')}
          {internet.length > 0 ? (
            <span className="ml-1.5 rounded-full bg-background/20 px-1.5 text-[10px]">{internet.length}</span>
          ) : null}
        </Button>
        <Button
          type="button"
          size="sm"
          variant={resolvedTab === 'harness' ? 'default' : 'outline'}
          onClick={() => setTab('harness')}
        >
          {t('verify.harness')}
          {harness.length > 0 ? (
            <span className="ml-1.5 rounded-full bg-background/20 px-1.5 text-[10px]">{harness.length}</span>
          ) : null}
        </Button>
      </div>

      {error ? (
        <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </div>
      ) : null}

      {items.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">{emptyHint}</CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {items.map((item) => {
            const key = `${resolvedTab}-${item.id}`
            const busy = busyKey === key
            return (
              <Card key={key}>
                <CardHeader className="pb-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1">
                      <CardTitle className="text-base">
                        <Link className="hover:underline" to={`/vulns/${item.id}`}>
                          #{item.id} {item.title}
                        </Link>
                      </CardTitle>
                      <CardDescription>
                        {t('project.fallback')}{' '}
                        <Link className="hover:underline" to={`/projects/${item.project_id}`}>
                          {item.project_name || `#${item.project_id}`}
                        </Link>
                        {' · '}
                        {formatDateTime(item.updated_at)}
                      </CardDescription>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="outline">{t('verifier.awaiting')}</Badge>
                      {item.vuln_type ? <Badge variant="secondary">{item.vuln_type}</Badge> : null}
                      {item.severity_score != null ? (
                        <Badge
                          className={severityScoreBadgeClass(item.severity_score, item.cvss_vector)}
                          title={item.cvss_vector || undefined}
                        >
                          {formatSeverityScore(item.severity_score, item.severity, item.cvss_vector)}
                        </Badge>
                      ) : formatSeverity(item.severity) ? (
                        <Badge variant="outline">{formatSeverity(item.severity)}</Badge>
                      ) : null}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="whitespace-pre-wrap rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-100/90">
                    {item.reason}
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-muted-foreground" htmlFor={`inst-${key}`}>
                      {resolvedTab === 'internet' ? t('consent.hintInternet') : t('consent.hintHarness')}
                    </label>
                    <Textarea
                      id={`inst-${key}`}
                      rows={3}
                      placeholder={
                        resolvedTab === 'internet' ? t('consent.phInternet') : t('consent.phHarness')
                      }
                      value={instructions[key] || ''}
                      disabled={busy}
                      onChange={(e) =>
                        setInstructions((prev) => ({ ...prev, [key]: e.target.value }))
                      }
                    />
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" disabled={busy} onClick={() => submit(item.id, 'skip')}>
                      {busy ? <Loader2Icon className="mr-2 h-4 w-4 animate-spin" /> : null}
                      {resolvedTab === 'internet' ? t('consent.skip') : t('consent.staticOnly')}
                    </Button>
                    <Button disabled={busy} onClick={() => submit(item.id, 'continue')}>
                      {busy ? <Loader2Icon className="mr-2 h-4 w-4 animate-spin" /> : null}
                      {resolvedTab === 'internet' ? t('consent.continueInternet') : t('consent.continueHarness')}
                    </Button>
                    <Link
                      className="inline-flex h-8 items-center rounded-lg px-2.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
                      to={`/vulns/${item.id}`}
                    >
                      {t('consent.viewVuln')}
                    </Link>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
