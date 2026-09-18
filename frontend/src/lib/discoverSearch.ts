import { api, type GithubDiscoverSearch } from '../api'
import { readJsonCache, writeJsonCache } from './listCache'

export const DISCOVER_STATUS_KEY = 'vh:discover-status'

export type DiscoverUiStatus = {
  error: string
  warning: string
  lastAdded: number | null
  searching: boolean
  limit: number
}

const DEFAULT_STATUS: DiscoverUiStatus = {
  error: '',
  warning: '',
  lastAdded: null,
  searching: false,
  limit: 5,
}

export type DiscoverSearchOutcome = {
  result?: GithubDiscoverSearch
  error?: unknown
}

type DiscoverSearchJob = {
  limit: number
  prompt: string
  promise: Promise<DiscoverSearchOutcome>
}

let job: DiscoverSearchJob | null = null
const listeners = new Set<() => void>()

function notify() {
  for (const fn of listeners) fn()
}

export function readDiscoverStatus(): DiscoverUiStatus {
  const cached = readJsonCache<Partial<DiscoverUiStatus>>(DISCOVER_STATUS_KEY)
  if (!cached || typeof cached !== 'object') return { ...DEFAULT_STATUS }
  const limit = Number(cached.limit)
  return {
    error: typeof cached.error === 'string' ? cached.error : '',
    warning: typeof cached.warning === 'string' ? cached.warning : '',
    lastAdded: typeof cached.lastAdded === 'number' ? cached.lastAdded : null,
    searching: Boolean(job) || Boolean(cached.searching),
    limit: Number.isFinite(limit) && limit >= 1 ? Math.min(20, Math.trunc(limit)) : 5,
  }
}

export function writeDiscoverStatus(next: Partial<DiscoverUiStatus>): DiscoverUiStatus {
  const prev = readDiscoverStatus()
  const merged: DiscoverUiStatus = {
    error: next.error ?? prev.error,
    warning: next.warning ?? prev.warning,
    lastAdded: next.lastAdded === undefined ? prev.lastAdded : next.lastAdded,
    searching: next.searching ?? Boolean(job),
    limit: next.limit ?? prev.limit,
  }
  writeJsonCache(DISCOVER_STATUS_KEY, merged)
  return merged
}

export function subscribeDiscoverSearch(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function getDiscoverSearchJob(): DiscoverSearchJob | null {
  return job
}

export function isDiscoverSearchRunning(): boolean {
  return job != null
}

export function startDiscoverSearch(limit: number, prompt: string): Promise<DiscoverSearchOutcome> {
  if (job) return job.promise
  const current: DiscoverSearchJob = {
    limit,
    prompt,
    promise: Promise.resolve({}),
  }
  current.promise = api
    .searchDiscoveries(limit, prompt)
    .then((result) => ({ result }))
    .catch((error: unknown) => ({ error }))
    .finally(() => {
      if (job === current) job = null
      notify()
    })
  job = current
  notify()
  return current.promise
}
