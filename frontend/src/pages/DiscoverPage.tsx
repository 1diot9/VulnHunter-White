import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2Icon, PlusIcon, RefreshCwIcon, StarIcon, Trash2Icon } from 'lucide-react'
import { api, formatApiError, type GithubCandidate } from '../api'
import { CreateProjectDialog } from '../components/CreateProjectDialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { formatDateTime, formatTargetKind, type TargetKind } from '@/lib/utils'
import { useI18n } from '@/i18n'
import { readJsonCache, writeJsonCache } from '../lib/listCache'

const DEFAULT_LIMIT = 5
const DISCOVER_CACHE_KEY = 'vh:discoveries'

function kindBadgeClass(kind: string): string {
  if (kind === 'library') return 'border-sky-500/40 bg-sky-500/10 text-sky-200'
  if (kind === 'mixed') return 'border-amber-500/40 bg-amber-500/10 text-amber-200'
  return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
}

function isImported(c: GithubCandidate): boolean {
  return c.status === 'imported' || c.project_id != null
}

function CandidateCard({
  candidate: c,
  imported,
  busy,
  searching,
  onCreate,
  onDismiss,
}: {
  candidate: GithubCandidate
  imported: boolean
  busy: boolean
  searching: boolean
  onCreate: (c: GithubCandidate) => void
  onDismiss: (c: GithubCandidate) => void
}) {
  const { t } = useI18n()
  return (
    <Card>
      <CardHeader className="gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          <CardTitle className="truncate text-base">
            <a href={c.html_url} target="_blank" rel="noreferrer" className="hover:underline">
              {c.full_name}
            </a>
          </CardTitle>
          <CardDescription className="line-clamp-2">{c.description || t('discover.noDesc')}</CardDescription>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Badge variant="outline" className={kindBadgeClass(c.target_kind)}>
            {formatTargetKind(c.target_kind)}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          {imported && c.project_id != null ? (
            <Link
              to={`/projects/${c.project_id}`}
              className="inline-flex h-7 items-center justify-center rounded-lg border border-border bg-background px-2.5 text-[0.8rem] font-medium hover:bg-muted"
            >
              {t('discover.viewProject')}
            </Link>
          ) : (
            <Button size="sm" className="gap-1.5" disabled={busy} onClick={() => onCreate(c)}>
              <PlusIcon className="size-4" />
              {t('home.create')}
            </Button>
          )}
          <Button
            size="sm"
            variant="outline"
            className="gap-1.5 text-muted-foreground hover:text-destructive"
            disabled={busy || searching}
            title={t('discover.dismissTip')}
            onClick={() => onDismiss(c)}
          >
            {busy ? <Loader2Icon className="size-4 animate-spin" /> : <Trash2Icon className="size-4" />}
            {t('discover.dismiss')}
          </Button>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <StarIcon className="size-3.5" />
            {c.stars}
          </span>
          {c.language ? <span>{c.language}</span> : null}
          <span>{t('discover.pushed', { time: formatDateTime(c.pushed_at) })}</span>
          <span>{t('discover.found', { time: formatDateTime(c.discovered_at) })}</span>
          {c.latest_ghsa_url ? (
            <a
              href={c.latest_ghsa_url}
              target="_blank"
              rel="noreferrer"
              className="text-sky-300 hover:underline"
            >
              {c.latest_ghsa_id || 'Advisory'}
            </a>
          ) : c.latest_ghsa_id ? (
            <span>{c.latest_ghsa_id}</span>
          ) : null}
          {c.target_kind_reason ? (
            <span className="max-w-xl truncate" title={c.target_kind_reason}>
              {c.target_kind_reason}
            </span>
          ) : null}
        </div>
      </CardContent>
    </Card>
  )
}

export default function DiscoverPage() {
  const { t } = useI18n()
  const cached = readJsonCache<{ items: GithubCandidate[]; total: number }>(DISCOVER_CACHE_KEY)
  const [items, setItems] = useState<GithubCandidate[]>(cached?.items ?? [])
  const [total, setTotal] = useState(cached?.total ?? 0)
  const [limit, setLimit] = useState(DEFAULT_LIMIT)
  const [loading, setLoading] = useState(!cached)
  const [searching, setSearching] = useState(false)
  const [dismissingId, setDismissingId] = useState<number | null>(null)
  const [error, setError] = useState('')
  const [warning, setWarning] = useState('')
  const [lastAdded, setLastAdded] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [prefillUrl, setPrefillUrl] = useState('')
  const [prefillKind, setPrefillKind] = useState<TargetKind | undefined>(undefined)

  const { pending, created } = useMemo(() => {
    const pending: GithubCandidate[] = []
    const created: GithubCandidate[] = []
    for (const c of items) {
      if (isImported(c)) created.push(c)
      else pending.push(c)
    }
    return { pending, created }
  }, [items])

  const load = useCallback((showLoading = false) => {
    if (showLoading) setLoading(true)
    return api
      .listDiscoveries({ limit: 200, offset: 0 })
      .then((data) => {
        setItems(data.items)
        setTotal(data.total)
        writeJsonCache(DISCOVER_CACHE_KEY, { items: data.items, total: data.total })
        setError('')
      })
      .catch((e) => setError(formatApiError(e)))
      .finally(() => {
        if (showLoading) setLoading(false)
      })
  }, [])

  useEffect(() => {
    void load(true)
  }, [load])

  async function onSearch() {
    setSearching(true)
    setError('')
    setWarning('')
    setLastAdded(null)
    try {
      const n = Math.max(1, Math.min(20, Number(limit) || DEFAULT_LIMIT))
      const result = await api.searchDiscoveries(n)
      setLastAdded(result.added)
      if (result.warning) setWarning(result.warning)
      await load(false)
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setSearching(false)
    }
  }

  function openCreate(c: GithubCandidate) {
    const kind = (c.target_kind || 'web') as TargetKind
    setPrefillUrl(c.html_url || `https://github.com/${c.full_name}`)
    setPrefillKind(kind)
    setCreateOpen(true)
  }

  async function onDismiss(c: GithubCandidate) {
    if (dismissingId != null) return
    setDismissingId(c.id)
    setError('')
    try {
      await api.dismissDiscovery(c.id)
      await load(false)
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setDismissingId(null)
    }
  }

  function renderList(list: GithubCandidate[], imported: boolean) {
    return (
      <div className="grid gap-3">
        {list.map((c) => (
          <CandidateCard
            key={c.id}
            candidate={c}
            imported={imported}
            busy={dismissingId === c.id}
            searching={searching}
            onCreate={openCreate}
            onDismiss={(item) => void onDismiss(item)}
          />
        ))}
      </div>
    )
  }

  return (
    <div className="w-full space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">{t('nav.discover')}</h1>
          <p className="mt-1 text-sm text-slate-400">{t('discover.subtitle')}</p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label htmlFor="discover-limit" className="text-xs text-muted-foreground">
              {t('discover.limit')}
            </Label>
            <Input
              id="discover-limit"
              type="number"
              min={1}
              max={20}
              className="w-24"
              value={limit}
              disabled={searching}
              onChange={(e) => setLimit(Number(e.target.value) || DEFAULT_LIMIT)}
            />
          </div>
          <Button disabled={searching} onClick={() => void onSearch()} className="gap-2">
            {searching ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            {searching ? t('discover.searching') : t('discover.search')}
          </Button>
        </div>
      </div>

      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {warning ? <p className="text-sm text-amber-200">{warning}</p> : null}
      {lastAdded != null ? (
        <p className="text-sm text-muted-foreground">
          {t('discover.addedPrefix')}{' '}
          <span className="font-medium text-foreground">{lastAdded}</span>{' '}
          {t('discover.addedSuffix')}
          {total > 0
            ? t('discover.addedSummary', {
                total,
                pending: pending.length,
                created: created.length,
              })
            : null}
        </p>
      ) : null}

      <CreateProjectDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        initialUrl={prefillUrl}
        initialTargetKind={prefillKind}
        onCreated={async () => {
          await load(false)
        }}
      />

      {loading ? (
        <div className="flex min-h-[30vh] items-center justify-center text-sm text-muted-foreground">
          <Loader2Icon className="mr-2 size-4 animate-spin" />
          {t('common.loading')}
        </div>
      ) : items.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('discover.emptyTitle')}</CardTitle>
            <CardDescription>{t('discover.emptyDesc')}</CardDescription>
          </CardHeader>
        </Card>
      ) : (
        <div className="space-y-8">
          <section className="space-y-3" aria-labelledby="discover-pending-heading">
            <div className="flex items-baseline gap-2">
              <h2 id="discover-pending-heading" className="text-sm font-medium text-slate-200">
                {t('discover.pending')}
              </h2>
              <span className="text-xs text-muted-foreground">{pending.length}</span>
            </div>
            {pending.length === 0 ? (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('discover.pendingEmptyTitle')}</CardTitle>
                  <CardDescription>{t('discover.pendingEmptyDesc')}</CardDescription>
                </CardHeader>
              </Card>
            ) : (
              renderList(pending, false)
            )}
          </section>

          <section className="space-y-3" aria-labelledby="discover-created-heading">
            <div className="flex items-baseline gap-2">
              <h2 id="discover-created-heading" className="text-sm font-medium text-slate-200">
                {t('discover.created')}
              </h2>
              <span className="text-xs text-muted-foreground">{created.length}</span>
            </div>
            {created.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('discover.createdEmpty')}</p>
            ) : (
              renderList(created, true)
            )}
          </section>
        </div>
      )}
    </div>
  )
}
