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
    default:
      return '未分层'
  }
}

export function formatTrackingStatus(value: string | null | undefined): string {
  switch (value) {
    case 'submitted':
      return '已提交'
    case 'ignored':
      return '已忽略'
    default:
      return '未标记'
  }
}

export function formatVerifierStatus(value: string | null | undefined): string | null {
  switch (value) {
    case 'pending':
      return '互联网验证中'
    case 'verified':
      return '互联网已复现'
    case 'failed':
      return '互联网未复现'
    case 'skipped':
      return '互联网验证跳过'
    default:
      return null
  }
}

export function formatVerifierTargetStatus(value: string | null | undefined): string {
  switch (value) {
    case 'success':
      return '成功'
    case 'fail':
      return '失败'
    case 'untested':
      return '未测'
    default:
      return value?.trim() || '未测'
  }
}

export const AUDIT_MODE_OPTIONS = [
  {
    value: 'bounty' as const,
    label: '赏金模式',
    short: '只报默认可利用的高危害漏洞',
    hint:
      '只收录默认可利用的高危害类型（RCE、注入、任意文件操作、越权、存储型 XSS、源码硬编码密钥等）。CORS、反射 XSS、缺速率限制等低危害项不入库；配置文件里用户可改的口令不算硬编码密钥。利用须在默认配置或应用自身配置下成立。',
  },
  {
    value: 'full' as const,
    label: '全量模式',
    short: '同时收录低危害难利用项',
    hint:
      '除高危害外，也收录难以利用但仍能打出差异的项（CORS、反射 XSS、缺速率限制、安全头等），由 Reviewer 标为低危害难利用。',
  },
] as const

export type AuditMode = (typeof AUDIT_MODE_OPTIONS)[number]['value']

export const BOUNTY_SCOPE_ROWS = [
  { type: 'RCE', included: true, note: '命令注入、代码执行等' },
  { type: 'SSTI', included: true, note: '' },
  { type: '反序列化 / JNDI', included: true, note: '' },
  { type: 'SQL 注入', included: true, note: '' },
  { type: 'XML 注入 / XXE', included: true, note: '' },
  { type: '任意文件操作', included: true, note: '读 / 写 / 删 / 改 / 复制 / 解压穿越等' },
  { type: '文件上传', included: true, note: '' },
  { type: '文件包含 / 目录遍历', included: true, note: '' },
  { type: '能打内网的 SSRF', included: true, note: '内网、云元数据或本机敏感口' },
  { type: '敏感信息泄露', included: true, note: '' },
  { type: '认证绕过', included: true, note: '' },
  { type: '越权', included: true, note: '' },
  { type: 'DoS', included: true, note: '' },
  { type: '存储型 XSS', included: true, note: '须持久化后在其他用户浏览器执行；不要把反射 XSS 写成存储型' },
  { type: '源码硬编码密钥', included: true, note: '仅程序常量中的 JWT / AES / DES / HMAC secret、私钥' },
  { type: '其他实际危害', included: true, note: '须证明代码执行、敏感数据泄露、越权读写删或任意文件操作等' },
  { type: '仅公网 SSRF', included: false, note: '打不到内网 / 元数据 / 本机敏感口' },
  { type: '反射 XSS / DOM XSS / Self-XSS', included: false, note: '' },
  { type: 'CORS / 安全头缺失', included: false, note: '含 ACAO 反射、CSP、X-Frame-Options 等' },
  { type: '开放重定向', included: false, note: '除非能升级为鉴权劫持、token 盗取等实际危害' },
  { type: '缺速率限制 / 验证码爆破', included: false, note: '无进一步危害时不收录' },
  { type: '弱随机 / 可预测 token', included: false, note: '除非直接导致认证绕过' },
  { type: '配置文件默认口令', included: false, note: 'application.yml、.env、compose、文档里用户可改的口令或密钥' },
  { type: '纯配置加固建议', included: false, note: '信息性扫描项' },
] as const

export const BOUNTY_SCOPE_PREMISE =
  '利用须在默认配置，或只改应用自身配置选项下成立。禁止种文件、改非应用配置、组合第二个独立漏洞。全量模式额外收录上表「不收录」中仍能打出差异的项，由 Reviewer 标为低危害难利用。'

export function formatAuditMode(value: string | null | undefined): string {
  return AUDIT_MODE_OPTIONS.find((o) => o.value === value)?.label ?? AUDIT_MODE_OPTIONS[0].label
}

export function formatAuditModeHint(value: string | null | undefined): string {
  return AUDIT_MODE_OPTIONS.find((o) => o.value === value)?.hint ?? AUDIT_MODE_OPTIONS[0].hint
}

export function formatProjectRunStatus(
  status: string | null | undefined,
  projectPaused?: boolean,
): '运行中' | '已暂停' | '已停止' | '已完成' {
  if (status === 'completed') return '已完成'
  if (status === 'paused' || projectPaused) return '已暂停'
  if (status === 'cancelled' || status === 'error') return '已停止'
  return '运行中'
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
