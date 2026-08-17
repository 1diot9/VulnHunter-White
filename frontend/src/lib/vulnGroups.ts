import type { Vuln } from '../api'

export type VulnGroup = {
  id: string
  rootCauseKey: string | null
  primary: Vuln
  others: Vuln[]
}

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

export function rootCauseGroupKey(v: Pick<Vuln, 'id' | 'project_id' | 'root_cause_key'>): string {
  const key = (v.root_cause_key || '').trim()
  return key ? `${v.project_id}::${key}` : `id:${v.id}`
}

export function vulnImpactRank(v: Pick<Vuln, 'severity' | 'severity_score' | 'status' | 'submission_tier'>): number {
  const severity = SEVERITY_RANK[v.severity] ?? 0
  const score = v.severity_score ?? 0
  const status = STATUS_RANK[v.status] ?? 0
  const tier = TIER_RANK[v.submission_tier ?? ''] ?? 0
  return status * 1_000_000 + severity * 10_000 + score * 100 + tier
}

function compareVulns(a: Vuln, b: Vuln): number {
  const d = vulnImpactRank(b) - vulnImpactRank(a)
  if (d !== 0) return d
  return a.id - b.id
}

/** Keep API order for groups; collapse same root_cause_key onto the highest-impact report. */
export function groupVulnsByRootCause(vulns: Vuln[]): VulnGroup[] {
  const buckets = new Map<string, Vuln[]>()
  const order: string[] = []
  for (const v of vulns) {
    const groupKey = rootCauseGroupKey(v)
    if (!buckets.has(groupKey)) {
      buckets.set(groupKey, [])
      order.push(groupKey)
    }
    buckets.get(groupKey)!.push(v)
  }
  return order.map((groupKey) => {
    const items = buckets.get(groupKey)!
    const sorted = [...items].sort(compareVulns)
    const primary = sorted[0]
    const key = (primary.root_cause_key || '').trim()
    return {
      id: groupKey,
      rootCauseKey: key || null,
      primary,
      others: sorted.slice(1),
    }
  })
}
