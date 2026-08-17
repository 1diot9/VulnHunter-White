import type { Vuln } from '../api'

export type VulnGroup = {
  id: string
  rootCauseKey: string | null
  primary: Vuln
  others: Vuln[]
}

export type VulnTierFilter =
  | 'all'
  | 'cve_candidate'
  | 'low_impact'
  | 'duplicate_grouped'
  | 'needs_more_evidence'
  | 'untiered'

const SEVERITY_RANK: Record<string, number> = {
  critical: 50,
  high: 40,
  medium: 30,
  low: 20,
  pending: 10,
}

const STATUS_RANK: Record<string, number> = {
  confirmed: 50,
  static_only: 40,
  pending_review: 30,
  returned: 20,
  fixing: 15,
  false_positive: 0,
}

const TIER_RANK: Record<string, number> = {
  cve_candidate: 40,
  needs_more_evidence: 25,
  low_impact: 20,
  advisory_only: 20,
  hardening: 20,
  duplicate_grouped: 10,
}

const KEY_TOKEN_STOP = new Set([
  'controller',
  'service',
  'filter',
  'util',
  'utils',
  'impl',
  'config',
  'handler',
  'action',
  'api',
  'other',
  'requirespermissions',
  'missing',
  'permissions',
])

const FILE_SUFFIX = /(Mapper|ServiceImpl|Service|Controller|Endpoint|Impl|Helper|Filter|Util|Utils|Config)$/i

export function canonicalRootCauseKey(raw: string | null | undefined): string {
  return (raw || '')
    .trim()
    .toLowerCase()
    .replace(/[：]/g, ':')
    .replace(/\s+/g, '')
}

export function rootCauseGroupKey(v: Pick<Vuln, 'id' | 'project_id' | 'root_cause_key'>): string {
  const key = canonicalRootCauseKey(v.root_cause_key)
  return key ? `${v.project_id}::${key}` : `id:${v.id}`
}

export function vulnImpactRank(v: Pick<Vuln, 'severity' | 'severity_score' | 'status' | 'submission_tier'>): number {
  const severity = SEVERITY_RANK[v.severity] ?? 0
  const score = v.severity_score ?? 0
  const status = STATUS_RANK[v.status] ?? 0
  const tier = TIER_RANK[v.submission_tier ?? ''] ?? 0
  return status * 1_000_000 + severity * 10_000 + score * 100 + tier
}

function isDuplicate(v: Pick<Vuln, 'submission_tier'>): boolean {
  return v.submission_tier === 'duplicate_grouped'
}

function compareImpact(a: Vuln, b: Vuln): number {
  const d = vulnImpactRank(b) - vulnImpactRank(a)
  if (d !== 0) return d
  return a.id - b.id
}

function preferPrimary(a: Vuln, b: Vuln): number {
  const da = isDuplicate(a) ? 0 : 1
  const db = isDuplicate(b) ? 0 : 1
  if (da !== db) return db - da
  return compareImpact(a, b)
}

function fileFamily(path: string | null | undefined): string {
  if (!path) return ''
  const base = path.replace(/\\/g, '/').split('/').pop() || ''
  const noExt = base.replace(/\.[^.]+$/, '')
  return noExt.replace(FILE_SUFFIX, '').toLowerCase()
}

function sameFileFamily(a?: string | null, b?: string | null): boolean {
  const fa = fileFamily(a)
  const fb = fileFamily(b)
  if (fa.length < 6 || fb.length < 6) return false
  return fa === fb || fa.includes(fb) || fb.includes(fa)
}

function sameFilePath(a?: string | null, b?: string | null): boolean {
  if (!a || !b) return false
  return a.replace(/\\/g, '/') === b.replace(/\\/g, '/')
}

function keyTokens(key: string): string[] {
  return canonicalRootCauseKey(key)
    .split(/[:_./\\-]+/)
    .filter((token) => token.length >= 6 && !KEY_TOKEN_STOP.has(token))
}

function fileMatchesTokens(filePath: string | null | undefined, tokens: string[]): boolean {
  if (!filePath || !tokens.length) return false
  const norm = filePath.replace(/\\/g, '/').toLowerCase()
  return tokens.some((token) => norm.includes(token))
}

function relatedToDuplicate(dup: Vuln, other: Vuln): boolean {
  if (other.vuln_type !== dup.vuln_type) return false
  const tokens = keyTokens(dup.root_cause_key || '')
  return (
    sameFilePath(dup.file_path, other.file_path) ||
    fileMatchesTokens(other.file_path, tokens) ||
    sameFileFamily(dup.file_path, other.file_path)
  )
}

function findAttachParent(dup: Vuln, pool: Vuln[]): Vuln | null {
  const others = pool.filter((v) => v.id !== dup.id && v.project_id === dup.project_id)
  const key = canonicalRootCauseKey(dup.root_cause_key)
  const sameKey = others.filter((v) => key && canonicalRootCauseKey(v.root_cause_key) === key)
  const sameKeyParents = sameKey.filter((v) => !isDuplicate(v))
  if (sameKeyParents.length) return [...sameKeyParents].sort(preferPrimary)[0]
  if (sameKey.length) return [...sameKey].sort(preferPrimary)[0]

  const related = others.filter((v) => !isDuplicate(v) && relatedToDuplicate(dup, v))
  if (related.length) return [...related].sort(preferPrimary)[0]
  return null
}

function matchesTier(v: Vuln, tier: VulnTierFilter): boolean {
  if (tier === 'all') return true
  if (tier === 'untiered') return !v.submission_tier
  if (tier === 'low_impact') return ['low_impact', 'hardening', 'advisory_only'].includes(v.submission_tier || '')
  return v.submission_tier === tier
}

/** Keep API order for parents; nest same-root-cause / duplicate_grouped / merged reports under the original. */
export function groupVulnsByRootCause(vulns: Vuln[]): VulnGroup[] {
  const parentOf = new Map<number, number>()

  const setParent = (childId: number, parentId: number) => {
    if (childId === parentId) return
    const seen = new Set<number>([childId])
    let cursor: number | undefined = parentId
    while (cursor != null) {
      if (seen.has(cursor)) return
      seen.add(cursor)
      cursor = parentOf.get(cursor)
    }
    parentOf.set(childId, parentId)
  }

  // Explicit merges first: status=merged + merged_into_id
  const byId = new Map(vulns.map((v) => [v.id, v]))
  for (const v of vulns) {
    if (v.status !== 'merged' || v.merged_into_id == null) continue
    if (byId.has(v.merged_into_id)) setParent(v.id, v.merged_into_id)
  }

  const buckets = new Map<string, Vuln[]>()
  for (const v of vulns) {
    if (v.status === 'merged') continue
    const key = canonicalRootCauseKey(v.root_cause_key)
    if (!key) continue
    const gk = `${v.project_id}::${key}`
    const list = buckets.get(gk)
    if (list) list.push(v)
    else buckets.set(gk, [v])
  }
  for (const items of buckets.values()) {
    if (items.length < 2) continue
    const primary = [...items].sort(preferPrimary)[0]
    for (const v of items) {
      if (v.id !== primary.id) setParent(v.id, primary.id)
    }
  }

  for (const v of vulns) {
    if (!isDuplicate(v) || parentOf.has(v.id)) continue
    const parent = findAttachParent(v, vulns)
    if (parent) setParent(v.id, parent.id)
  }

  const resolveRoot = (id: number): number => {
    let cur = id
    const seen = new Set<number>()
    while (parentOf.has(cur)) {
      if (seen.has(cur)) return cur
      seen.add(cur)
      cur = parentOf.get(cur) as number
    }
    return cur
  }

  const children = new Map<number, Vuln[]>()
  for (const v of vulns) {
    const root = resolveRoot(v.id)
    if (root === v.id) continue
    const list = children.get(root)
    if (list) list.push(v)
    else children.set(root, [v])
  }

  const groups: VulnGroup[] = []
  for (const v of vulns) {
    // Merged rows never stand alone as a card
    if (v.status === 'merged') continue
    if (resolveRoot(v.id) !== v.id) continue
    const others = (children.get(v.id) || []).slice().sort(compareImpact)
    const key =
      canonicalRootCauseKey(v.root_cause_key) ||
      others.map((o) => canonicalRootCauseKey(o.root_cause_key)).find(Boolean) ||
      ''
    groups.push({
      id: key ? `${v.project_id}::${key}` : `id:${v.id}`,
      rootCauseKey: (v.root_cause_key || others.find((o) => o.root_cause_key)?.root_cause_key || '').trim() || null,
      primary: v,
      others,
    })
  }
  return groups
}

export function filterVulnGroups(groups: VulnGroup[], tier: VulnTierFilter = 'all'): VulnGroup[] {
  if (tier === 'all') return groups
  const out: VulnGroup[] = []
  for (const group of groups) {
    const members = [group.primary, ...group.others]
    if (tier === 'duplicate_grouped') {
      const dups = members.filter(isDuplicate)
      if (!dups.length) continue
      if (isDuplicate(group.primary)) {
        out.push({ ...group, others: group.others.filter(isDuplicate) })
      } else {
        out.push({ ...group, others: group.others.filter(isDuplicate) })
      }
      continue
    }
    const kept = members.filter((v) => matchesTier(v, tier))
    if (!kept.length) continue
    const primary = kept.find((v) => v.id === group.primary.id) ?? kept[0]
    out.push({
      ...group,
      primary,
      others: kept.filter((v) => v.id !== primary.id),
    })
  }
  return out
}
