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

export function formatEvidenceLevel(value: string | null | undefined): string | null {
  switch (value) {
    case 'harness':
      return '局部验证'
    case 'dynamic':
      return '动态验证'
    case 'mcp':
      return '动态验证 · MCP'
    default:
      return null
  }
}

const VULN_STATUS_LABEL: Record<string, string> = {
  pending_review: '待审',
  false_positive: '误报',
  returned: '已打回',
  merged: '已并入',
  fixing: '修复中',
}

/** Confirmed vulns fold evidence into one badge: 已确认-仅静态 / 局部验证 / 动态验证. */
export function formatVulnStatus(
  status: string | null | undefined,
  evidenceLevel?: string | null,
): string {
  const s = (status || '').trim()
  if (s === 'confirmed' || s === 'static_only') {
    const evidence = formatEvidenceLevel(evidenceLevel)
    return evidence ? `已确认-${evidence}` : '已确认-仅静态'
  }
  return VULN_STATUS_LABEL[s] || s
}

export function formatMiningPath(value: string | null | undefined): string | null {
  switch ((value || '').trim().toLowerCase()) {
    case 'heuristic':
      return '启发式挖掘'
    case 'fast':
      return '快速扫描'
    case 'bypass':
      return '历史漏洞绕过'
    default:
      return null
  }
}

export function formatConfigPremise(value: string | null | undefined): string | null {
  switch ((value || '').trim().toLowerCase()) {
    case 'default':
      return '默认配置'
    case 'specific':
      return '特定配置'
    default:
      return null
  }
}

export function formatProjectRef(projectId: number, projectName?: string | null): string {
  const name = (projectName || '').trim()
  if (!name || name === `项目 ${projectId}` || name === `项目 #${projectId}`) {
    return `项目 #${projectId}`
  }
  return `项目 #${projectId} ${name}`
}

export function formatVerifierStatus(value: string | null | undefined): string | null {
  switch (value) {
    case 'pending':
      return '互联网验证中'
    case 'awaiting_user':
      return '待用户确认'
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
      '只收录默认可利用的高危害类型（RCE、注入、任意文件操作、越权、存储型 XSS、1-click CSRF、有服务端机密危害的源码硬编码密钥等）。CORS、反射 XSS、普通 CSRF、缺速率限制等低危害项不入库；配置文件里用户可改的口令、前端传输混淆 AES/公开下发密钥不算。利用须在默认配置或应用自身配置下成立；提交时标明默认配置或特定配置，官方已警示的风险开关不算特定配置。',
  },
  {
    value: 'full' as const,
    label: '全量模式',
    short: '同时收录低危害难利用项',
    hint:
      '除高危害外，也收录难以利用但仍能打出差异的项（CORS、反射 XSS、缺速率限制、安全头、普通 CSRF 等），由 Reviewer 标为低危害难利用。',
  },
  {
    value: 'custom' as const,
    label: '自定义模式',
    short: '按设置页命名提示词判定范围',
    hint:
      '漏洞收录完全按所选自定义提示词（项目内快照）判定，无赏金模式代码硬闸门。请先在设置页创建自定义审计模式。',
  },
] as const

export type AuditMode = (typeof AUDIT_MODE_OPTIONS)[number]['value']

export const TARGET_KIND_OPTIONS = [
  {
    value: 'web' as const,
    label: 'Web 应用',
    short: 'HTTP / 非 HTTP 入口为主',
    hint: '按可部署应用审计：HTTP 与 WebSocket / RPC / MQ 等入口为 source。',
  },
  {
    value: 'library' as const,
    label: '组件库',
    short: 'Maven / pip / npm 等库',
    hint: '按组件审计：公开 API / 解析器为调用方可控入口；创建时默认局部验证、关闭 Verifier。',
  },
  {
    value: 'mixed' as const,
    label: '混合',
    short: '库核心 + demo 应用',
    hint: '优先挖库核心；demo/sample/examples 降权。创建时默认局部验证、关闭 Verifier。',
  },
] as const

export type TargetKind = (typeof TARGET_KIND_OPTIONS)[number]['value']

export function formatTargetKind(value: string | null | undefined): string {
  return TARGET_KIND_OPTIONS.find((o) => o.value === value)?.label ?? TARGET_KIND_OPTIONS[0].label
}

export function formatTargetKindHint(value: string | null | undefined): string {
  return TARGET_KIND_OPTIONS.find((o) => o.value === value)?.hint ?? TARGET_KIND_OPTIONS[0].hint
}

export function normalizeTargetKind(value: string | null | undefined): TargetKind {
  if (value === 'library' || value === 'mixed') return value
  return 'web'
}

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
  { type: '1-click CSRF', included: true, note: '受害者打开恶意页面后立即触发 RCE 或其他高危操作；不要把改资料/登出等普通 CSRF 写成 1-click' },
  { type: '源码硬编码密钥', included: true, note: '须为服务端机密：JWT/HMAC 签名、接口签名 secret、私钥、第三方 API Key、保护库内/备份密文等；能造成未授权危害' },
  { type: '其他实际危害', included: true, note: '须证明代码执行、敏感数据泄露、越权读写删或任意文件操作等' },
  { type: '仅公网 SSRF', included: false, note: '打不到内网 / 元数据 / 本机敏感口' },
  { type: '反射 XSS / DOM XSS / Self-XSS', included: false, note: '' },
  { type: '普通 CSRF / 仅缺 token', included: false, note: '改昵称、登出、点赞、发帖等低危状态变更；或需多次点击/二次确认' },
  { type: 'CORS / 安全头缺失', included: false, note: '含 ACAO 反射、CSP、X-Frame-Options 等' },
  { type: '开放重定向', included: false, note: '除非能升级为鉴权劫持、token 盗取等实际危害' },
  { type: '缺速率限制 / 验证码爆破', included: false, note: '无进一步危害时不收录' },
  { type: '弱随机 / 可预测 token', included: false, note: '除非直接导致认证绕过' },
  { type: '前端传输混淆 AES', included: false, note: '密钥在前端 JS 或故意公开下发；解开前端本就会解的字段 / 已拦截登录包不算 CVE' },
  { type: '配置文件默认口令', included: false, note: 'application.yml、.env、compose、文档里用户可改的口令或密钥' },
  { type: '纯配置加固建议', included: false, note: '信息性扫描项' },
] as const

export const BOUNTY_SCOPE_PREMISE =
  '利用须在默认配置，或只改应用自身配置选项下成立。提交时标明默认配置或特定配置；官方已警示的风险开关不算特定配置。禁止种文件、改非应用配置、组合第二个独立漏洞。全量模式额外收录上表「不收录」中仍能打出差异的项，由 Reviewer 标为低危害难利用。'

export function formatAuditMode(
  value: string | null | undefined,
  customName?: string | null,
): string {
  if (value === 'custom') {
    const name = (customName || '').trim()
    return name ? `自定义（${name}）` : '自定义模式'
  }
  return AUDIT_MODE_OPTIONS.find((o) => o.value === value)?.label ?? AUDIT_MODE_OPTIONS[0].label
}

export function formatAuditModeHint(
  value: string | null | undefined,
  customName?: string | null,
): string {
  if (value === 'custom') {
    const name = (customName || '').trim()
    return name
      ? `当前按自定义模式「${name}」的项目快照提示词判定漏洞范围；无赏金硬闸门。续跑后下一轮生效。`
      : AUDIT_MODE_OPTIONS.find((o) => o.value === 'custom')!.hint
  }
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

export function formatProjectStatus(status: string | null | undefined): string {
  switch (status) {
    case 'pending':
      return '待开始'
    case 'ingesting':
      return '导入中'
    case 'recon':
      return '侦察中'
    case 'auditing':
      return '挖掘中'
    case 'reviewing':
      return '审核中'
    case 'paused':
      return '已暂停'
    case 'completed':
      return '已完成'
    case 'cancelled':
      return '已停止'
    case 'error':
      return '出错'
    default:
      return status?.trim() || '—'
  }
}

export function projectStatusBadgeVariant(
  status: string | null | undefined,
): 'info' | 'success' | 'warning' | 'destructive' {
  if (status === 'completed') return 'success'
  if (status === 'paused') return 'warning'
  if (status === 'cancelled' || status === 'error') return 'destructive'
  return 'info'
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

export function formatSeverityScore(
  value: number | null | undefined,
  severity?: string | null,
): string | null {
  if (value == null || Number.isNaN(value)) return null
  const signed = value > 0 ? `+${value}` : String(value)
  const label = formatSeverity(severity)
  return label ? `${label}${signed}` : signed
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

export function formatSinkProgress(p: {
  sinks_done?: number | null
  sinks_queued?: number | null
}): string {
  return `快速扫描 ${p.sinks_done ?? 0}/${p.sinks_queued ?? 0}`
}

export function formatBypassProgress(p: {
  bypass_done?: number | null
  bypass_queued?: number | null
}): string {
  return `历史漏洞绕过 ${p.bypass_done ?? 0}/${p.bypass_queued ?? 0}`
}

export function formatMiningPaths(p: {
  heuristic_enabled?: boolean | null
  heuristic_lite?: boolean | null
  fast_enabled?: boolean | null
  bypass_enabled?: boolean | null
}): string {
  const heuristicOn = p.heuristic_enabled !== false
  const liteOn = heuristicOn && p.heuristic_lite === true
  const fastOn = p.fast_enabled === true
  const bypassOn = p.bypass_enabled === true
  const parts: string[] = []
  if (heuristicOn) parts.push(liteOn ? '启发式轻量' : '启发式挖掘')
  if (fastOn) parts.push('快速扫描')
  if (bypassOn) parts.push('历史漏洞绕过')
  return parts.join(' + ') || '启发式挖掘'
}

export function formatMiningProgress(p: {
  heuristic_enabled?: boolean | null
  heuristic_lite?: boolean | null
  fast_enabled?: boolean | null
  bypass_enabled?: boolean | null
  files_audited?: number | null
  files_weighted?: number | null
  files_skipped?: number | null
  files_total?: number | null
  files_weight100?: number | null
  files_weight100_audited?: number | null
  sinks_done?: number | null
  sinks_queued?: number | null
  bypass_done?: number | null
  bypass_queued?: number | null
}): string {
  const heuristicOn = p.heuristic_enabled !== false
  const liteOn = heuristicOn && p.heuristic_lite === true
  const fastOn = p.fast_enabled === true
  const bypassOn = p.bypass_enabled === true
  const parts: string[] = []
  if (heuristicOn && liteOn) {
    parts.push(`轻量入口 ${p.files_weight100_audited ?? 0}/${p.files_weight100 ?? 0}`)
  } else if (heuristicOn) {
    parts.push(formatFileProgress(p))
  }
  if (fastOn) parts.push(formatSinkProgress(p))
  if (bypassOn) parts.push(formatBypassProgress(p))
  return parts.join(' · ')
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
  max_token_usage?: number | null
}): string {
  const input = p.tokens_input ?? 0
  const output = p.tokens_output ?? 0
  const cached = p.tokens_cached ?? 0
  const cap = p.max_token_usage ?? 0
  const used = `输入 ${formatTokens(input)} / 输出 ${formatTokens(output)} / 缓存率 ${formatCacheRate(cached, input)}`
  if (cap > 0) return `${used} / 上限 ${formatTokens(cap)}`
  return used
}

export function tokenBudgetReached(p: {
  tokens_input?: number | null
  tokens_output?: number | null
  max_token_usage?: number | null
}): boolean {
  const cap = p.max_token_usage ?? 0
  if (cap <= 0) return false
  return (p.tokens_input ?? 0) + (p.tokens_output ?? 0) >= cap
}

export function saveBlob(blob: Blob, filename: string) {
  const a = document.createElement('a')
  const url = URL.createObjectURL(blob)
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || Number.isNaN(Number(bytes))) return '—'
  const n = Number(bytes)
  if (n < 1024) return `${Math.round(n)} B`
  const mb = n / (1024 * 1024)
  if (mb < 1024) return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`
  return `${(mb / 1024).toFixed(2)} GB`
}

export function containerStatusBadgeVariant(
  status: string | null | undefined,
): 'success' | 'warning' | 'destructive' | 'secondary' {
  const value = (status || '').toLowerCase()
  if (value === 'running') return 'success'
  if (value === 'paused' || value === 'restarting' || value === 'created') return 'warning'
  if (value === 'dead' || value === 'removing') return 'destructive'
  return 'secondary'
}
