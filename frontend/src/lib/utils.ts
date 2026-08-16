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
