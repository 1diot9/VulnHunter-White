import { projectRunBucket } from './utils'
import type { Project, ProjectList } from '../api'

export const PROJECT_LIST_CACHE_PREFIX = 'vh:projects:'
export const PROJECT_LIST_CHANGED_EVENT = 'vh:projects-changed'

export function readJsonCache<T>(key: string): T | null {
  try {
    const raw = sessionStorage.getItem(key)
    if (!raw) return null
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

export function writeJsonCache(key: string, value: unknown): void {
  try {
    sessionStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* quota / private mode */
  }
}

export function projectDetailCacheKey(id: number): string {
  return `vh:project:${id}`
}

export function projectPreviewCacheKey(id: number): string {
  return `vh:project-preview:${id}`
}

export function readProjectSnapshot<T extends { unchanged?: boolean; notModified?: boolean }>(
  id: number,
): { project: T; partial: boolean } | null {
  const full = readJsonCache<T>(projectDetailCacheKey(id))
  if (full && !full.unchanged && !full.notModified) {
    return { project: full, partial: false }
  }
  const preview = readJsonCache<T>(projectPreviewCacheKey(id))
  if (preview && !preview.unchanged && !preview.notModified) {
    return { project: preview, partial: true }
  }
  return null
}

type ProjectRunSnap = {
  status: string
  project_paused?: boolean
  t: number
}

function projectRunCacheKey(id: number): string {
  return `vh:project-run:${id}`
}

/** Remember the latest known run status so filter tabs don't show stale badges. */
export function rememberProjectRun(project: {
  id: number
  status: string
  project_paused?: boolean
}): void {
  writeJsonCache(projectRunCacheKey(project.id), {
    status: project.status,
    project_paused: project.project_paused,
    t: Date.now(),
  } satisfies ProjectRunSnap)
}

/** Overlay a newer network snapshot onto a stale per-filter list row. */
export function overlayProjectRun<
  T extends { id: number; status: string; project_paused?: boolean },
>(item: T): T {
  const snap = readJsonCache<ProjectRunSnap>(projectRunCacheKey(item.id))
  if (!snap || typeof snap.status !== 'string') return item
  if (snap.status === item.status && snap.project_paused === item.project_paused) return item
  return { ...item, status: snap.status, project_paused: snap.project_paused }
}

type ListCacheKey = {
  pageSize: number
  page: number
  search: string
  filter: 'all' | 'running' | 'paused' | 'completed'
}

function parseProjectsCacheKey(key: string): ListCacheKey | null {
  if (!key.startsWith(PROJECT_LIST_CACHE_PREFIX)) return null
  const parts = key.slice(PROJECT_LIST_CACHE_PREFIX.length).split(':')
  if (parts.length < 4) return null
  const filter = parts[parts.length - 1]
  if (filter !== 'all' && filter !== 'running' && filter !== 'paused' && filter !== 'completed') {
    return null
  }
  const pageSize = Number(parts[0])
  const page = Number(parts[1])
  if (!Number.isFinite(pageSize) || !Number.isFinite(page)) return null
  return { pageSize, page, search: parts.slice(2, -1).join(':'), filter }
}

function adjustStatusCounts(
  counts: ProjectList['status_counts'] | undefined,
  from: ReturnType<typeof projectRunBucket> | null,
  to: ReturnType<typeof projectRunBucket>,
): ProjectList['status_counts'] | undefined {
  if (!counts || from === to) return counts
  const next = { ...counts }
  if (from === 'running' || from === 'paused' || from === 'completed') {
    next[from] = Math.max(0, (next[from] || 0) - 1)
  }
  if (to === 'running' || to === 'paused' || to === 'completed') {
    next[to] = (next[to] || 0) + 1
  }
  return next
}

function mergeListItem(project: Project, previous?: Project): Project {
  return {
    ...(previous || project),
    ...project,
    status: project.status,
    project_paused: project.project_paused,
    phase: project.phase,
  }
}

/** Patch cached list pages so pause/resume shows up without waiting for the poll. */
export function applyProjectRunToListCaches(project: Project): void {
  const prevSnap = readJsonCache<{ status: string; project_paused?: boolean }>(
    projectRunCacheKey(project.id),
  )
  const to = projectRunBucket(project.status, project.project_paused)
  const from = prevSnap?.status
    ? projectRunBucket(prevSnap.status, prevSnap.project_paused)
    : null
  rememberProjectRun(project)
  writeJsonCache(projectPreviewCacheKey(project.id), project)

  const keys: string[] = []
  for (let i = 0; i < sessionStorage.length; i += 1) {
    const key = sessionStorage.key(i)
    if (key) keys.push(key)
  }
  for (const key of keys) {
    const parsed = parseProjectsCacheKey(key)
    if (!parsed) continue
    const data = readJsonCache<ProjectList>(key)
    if (!data || data.notModified || data.unchanged || !Array.isArray(data.items)) continue
    const existing = data.items.find((item) => item.id === project.id)
    let items = data.items.filter((item) => item.id !== project.id)
    const belongs = parsed.filter === 'all' || parsed.filter === to
    if (belongs && (parsed.page === 0 || existing)) {
      items = [mergeListItem(project, existing), ...items].slice(0, parsed.pageSize || items.length + 1)
    }
    writeJsonCache(key, {
      ...data,
      items,
      etag: '',
      status_counts: adjustStatusCounts(data.status_counts, from, to) || data.status_counts,
    })
  }
  window.dispatchEvent(new CustomEvent(PROJECT_LIST_CHANGED_EVENT))
}
