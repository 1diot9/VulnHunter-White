import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatAttackSurface(
  attackSurface: string | null | undefined,
  requiredAccount: string | null | undefined,
): string | null {
  if (attackSurface === 'frontend') return '前台'
  if (attackSurface === 'backend') {
    if (requiredAccount === 'admin') return '后台 · 管理员'
    if (requiredAccount === 'user') return '后台 · 普通权限'
    return '后台'
  }
  return null
}

export function formatSubmissionTier(value: string | null | undefined): string {
  switch (value) {
    case 'cve_candidate':
      return '有 CVE 价值'
    case 'low_impact':
    case 'advisory_only':
    case 'hardening':
      return '低危害难利用'
    case 'duplicate_grouped':
      return '同根因重复'
    case 'needs_more_evidence':
      return '证据不足'
    default:
      return '未分层'
  }
}

export function formatAuditMode(value: string | null | undefined): string {
  if (value === 'full') return '全量模式'
  return '赏金模式'
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  let s = value.trim()
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s) && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(s)) {
    s = `${s.replace(' ', 'T')}Z`
  }
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })
}

export function formatSeverity(value: string | null | undefined): string {
  switch (value) {
    case 'critical':
      return '严重'
    case 'high':
      return '高危'
    case 'medium':
      return '中危'
    case 'low':
      return '低危'
    case 'pending':
      return '待校准'
    default:
      return value || ''
  }
}

export function formatSeverityScore(value: number | null | undefined): string | null {
  if (value == null || Number.isNaN(value)) return null
  return `校准 ${value > 0 ? `+${value}` : value}`
}

export function severityScoreBadgeClass(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return ''
  if (value >= 5) return 'bg-red-500/20 text-red-100 ring-1 ring-red-500/30'
  if (value >= 3) return 'bg-orange-500/20 text-orange-100 ring-1 ring-orange-500/30'
  if (value >= 1) return 'bg-amber-500/15 text-amber-100 ring-1 ring-amber-500/25'
  return 'bg-slate-500/15 text-slate-200 ring-1 ring-slate-500/20'
}

export function formatFileProgress(p: {
  files_audited?: number | null
  files_weighted?: number | null
  files_skipped?: number | null
  files_total?: number | null
}): string {
  return `已审计 ${p.files_audited ?? 0} / 已定权 ${p.files_weighted ?? 0} / 已跳过 ${p.files_skipped ?? 0} / 共 ${p.files_total ?? 0}`
}

export function formatTokens(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return '—'
  const v = Math.round(n)
  if (v < 1000) return String(v)
  if (v < 1_000_000) {
    const k = v / 1000
    return `${k >= 100 ? Math.round(k) : k.toFixed(1).replace(/\.0$/, '')}k`
  }
  return `${(v / 1_000_000).toFixed(2).replace(/\.0$/, '')}M`
}

export function formatCacheRate(
  cached: number | null | undefined,
  input: number | null | undefined,
): string {
  const c = cached ?? 0
  const i = input ?? 0
  if (i <= 0) return '—'
  const pct = (c / i) * 100
  if (pct >= 10) return `${Math.round(pct)}%`
  return `${pct.toFixed(1).replace(/\.0$/, '')}%`
}

export function formatTokenUsage(p: {
  tokens_input?: number | null
  tokens_output?: number | null
  tokens_cached?: number | null
}): string {
  const input = p.tokens_input ?? 0
  const output = p.tokens_output ?? 0
  const cached = p.tokens_cached ?? 0
  return `输入 ${formatTokens(input)} / 输出 ${formatTokens(output)} / 缓存率 ${formatCacheRate(cached, input)}`
}
