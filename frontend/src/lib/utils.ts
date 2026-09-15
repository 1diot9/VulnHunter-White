import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { dateLocale, getLocale } from '@/i18n/locale'
import { t } from '@/i18n/t'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatAttackSurface(
  attackSurface: string | null | undefined,
  requiredAccount: string | null | undefined,
): string | null {
  if (attackSurface === 'frontend') return t('surface.frontend')
  if (attackSurface === 'backend') {
    if (requiredAccount === 'admin') return t('surface.backendAdmin')
    if (requiredAccount === 'user') return t('surface.backendUser')
    return t('surface.backend')
  }
  return null
}

export function formatSubmissionTier(value: string | null | undefined): string {
  switch (value) {
    case 'cve_candidate':
      return t('tier.cve')
    case 'low_impact':
    case 'advisory_only':
    case 'hardening':
      return t('tier.low')
    case 'duplicate_grouped':
      return t('tier.dup')
    default:
      return t('tier.unknown')
  }
}

export function formatExposureMode(value: string | null | undefined): string | null {
  switch (value) {
    case 'indirect_consumer':
      return t('exposure.indirect')
    case 'direct':
      return t('exposure.direct')
    default:
      return null
  }
}

/** Hover tooltip for the exposure-mode badge. */
export function exposureModeTooltip(
  mode: string | null | undefined,
  upstreamChainProven?: boolean | null,
): string | null {
  switch (mode) {
    case 'indirect_consumer':
      return upstreamChainProven ? t('exposure.tip.indirectProven') : t('exposure.tip.indirect')
    case 'direct':
      return t('exposure.tip.direct')
    default:
      return null
  }
}

export function formatTrackingStatus(value: string | null | undefined): string {
  switch (value) {
    case 'submitted':
      return t('track.submitted')
    case 'ignored':
      return t('track.ignored')
    default:
      return t('track.none')
  }
}

export function harnessVerificationTier(
  evidenceLevel: string | null | undefined,
  harnessDepth?: string | null,
): 'L1' | 'L2' | 'L3' | null {
  const evidence = (evidenceLevel || '').trim().toLowerCase()
  const depth = (harnessDepth || '').trim().toLowerCase() || 'sink'
  if (evidence === 'harness') {
    if (depth === 'module') return 'L2'
    return 'L1'
  }
  if (evidence === 'dynamic' && depth === 'integration') return 'L3'
  return null
}

/** Returns the L1/L2/L3 tooltip text for confirmed vulns with harness/dynamic evidence.
 * L1: mock harness 直调 sink；L2: mock harness 调模块层；L3: 集成验证起服务并跑 poc.py。 */
export function harnessTierTooltip(
  evidenceLevel?: string | null,
  harnessDepth?: string | null,
): string | null {
  const tier = harnessVerificationTier(evidenceLevel, harnessDepth)
  const evidence = (evidenceLevel || '').trim().toLowerCase()
  if (evidence === 'harness') {
    if (tier === 'L2') return t('harness.l2')
    return t('harness.l1')
  }
  if (evidence === 'dynamic' && tier === 'L3') return t('harness.l3')
  return null
}

export function formatEvidenceLevel(
  value: string | null | undefined,
  harnessDepth?: string | null,
): string | null {
  const tier = harnessVerificationTier(value, harnessDepth)
  switch (value) {
    case 'harness':
      return tier ? t('evidence.harnessTier', { tier }) : t('evidence.harness')
    case 'dynamic':
      return tier === 'L3' ? t('evidence.dynamicL3') : t('evidence.dynamic')
    case 'mcp':
      return t('evidence.mcp')
    default:
      return null
  }
}

const VULN_STATUS_KEYS: Record<string, string> = {
  pending_review: 'vulnStatus.pending_review',
  false_positive: 'vulnStatus.false_positive',
  returned: 'vulnStatus.returned',
  merged: 'vulnStatus.merged',
  fixing: 'vulnStatus.fixing',
}

export const FP_KIND_TIMEOUT = 'timeout'
export const FP_KIND_KNOWN_CVE_PATCHED = 'known_cve_patched'
export const FP_KIND_KNOWN_PUBLIC = 'known_public'
export const FP_KIND_SOURCE_FIXED = 'source_fixed'

/** Confirmed vulns fold evidence into one badge: 已确认-仅静态 / 局部验证 / 动态验证.
 * Timeout give-ups show 误报-审核超时; dedup FPs are 误报-已公开 or 误报-已修复. */
export function formatVulnStatus(
  status: string | null | undefined,
  evidenceLevel?: string | null,
  fpKind?: string | null,
  harnessDepth?: string | null,
): string {
  const s = (status || '').trim()
  if (s === 'confirmed' || s === 'static_only') {
    const evidence = formatEvidenceLevel(evidenceLevel, harnessDepth)
    return evidence ? t('vulnStatus.confirmedEvidence', { evidence }) : t('vulnStatus.confirmedStatic')
  }
  if (s === 'false_positive' && (fpKind || '').trim() === FP_KIND_TIMEOUT) {
    return t('vulnStatus.fpTimeout')
  }
  if (s === 'false_positive' && (fpKind || '').trim() === FP_KIND_KNOWN_PUBLIC) {
    return t('vulnStatus.fpPublic')
  }
  if (
    s === 'false_positive' &&
    ((fpKind || '').trim() === FP_KIND_SOURCE_FIXED ||
      (fpKind || '').trim() === FP_KIND_KNOWN_CVE_PATCHED)
  ) {
    return t('vulnStatus.fpFixed')
  }
  return VULN_STATUS_KEYS[s] ? t(VULN_STATUS_KEYS[s]) : s
}

export function formatMiningPath(value: string | null | undefined): string | null {
  switch ((value || '').trim().toLowerCase()) {
    case 'heuristic':
      return t('mining.heuristic')
    case 'fast':
      return t('mining.fast')
    case 'bypass':
      return t('mining.bypass')
    case 'unconstrained':
      return t('mining.unconstrained')
    default:
      return null
  }
}

export function formatConfigPremise(value: string | null | undefined): string | null {
  switch ((value || '').trim().toLowerCase()) {
    case 'default':
      return t('config.default')
    case 'specific':
      return t('config.specific')
    default:
      return null
  }
}

export function formatProjectRef(projectId: number, projectName?: string | null): string {
  const name = (projectName || '').trim()
  const fallbackZh = `项目 ${projectId}`
  const fallbackHash = `项目 #${projectId}`
  const fallbackEn = `Project ${projectId}`
  const fallbackEnHash = `Project #${projectId}`
  if (
    !name ||
    name === fallbackZh ||
    name === fallbackHash ||
    name === fallbackEn ||
    name === fallbackEnHash ||
    name === t('project.ref', { id: projectId })
  ) {
    return t('project.ref', { id: projectId })
  }
  return t('project.refNamed', { id: projectId, name })
}

export function formatVerifierStatus(value: string | null | undefined): string | null {
  switch (value) {
    case 'pending':
      return t('verifier.pending')
    case 'awaiting_user':
      return t('verifier.awaiting')
    case 'verified':
      return t('verifier.verified')
    case 'failed':
      return t('verifier.failed')
    case 'skipped':
      return t('verifier.skipped')
    default:
      return null
  }
}

export function formatVerifierTargetStatus(value: string | null | undefined): string {
  switch (value) {
    case 'success':
      return t('verifier.target.success')
    case 'fail':
      return t('verifier.target.fail')
    case 'untested':
      return t('verifier.target.untested')
    default:
      return value?.trim() || t('verifier.target.untested')
  }
}

export const AUDIT_MODE_VALUES = ['bounty', 'full', 'custom'] as const
export type AuditMode = (typeof AUDIT_MODE_VALUES)[number]

export function getAuditModeOptions() {
  return [
    {
      value: 'bounty' as const,
      label: t('audit.bounty'),
      short: t('audit.bountyShort'),
      hint: t('audit.bountyHint'),
    },
    {
      value: 'full' as const,
      label: t('audit.full'),
      short: t('audit.fullShort'),
      hint: t('audit.fullHint'),
    },
    {
      value: 'custom' as const,
      label: t('audit.custom'),
      short: t('audit.customShort'),
      hint: t('audit.customHint'),
    },
  ] as const
}

/** @deprecated use getAuditModeOptions() so labels follow UI locale */
export const AUDIT_MODE_OPTIONS = getAuditModeOptions()

export const TARGET_KIND_VALUES = ['web', 'library', 'mixed'] as const
export type TargetKind = (typeof TARGET_KIND_VALUES)[number]

export function getTargetKindOptions() {
  return [
    {
      value: 'web' as const,
      label: t('kind.web'),
      short: t('kind.webShort'),
      hint: t('kind.webHint'),
    },
    {
      value: 'library' as const,
      label: t('kind.library'),
      short: t('kind.libraryShort'),
      hint: t('kind.libraryHint'),
    },
    {
      value: 'mixed' as const,
      label: t('kind.mixed'),
      short: t('kind.mixedShort'),
      hint: t('kind.mixedHint'),
    },
  ] as const
}

/** @deprecated use getTargetKindOptions() so labels follow UI locale */
export const TARGET_KIND_OPTIONS = getTargetKindOptions()

export function formatTargetKind(value: string | null | undefined): string {
  const opts = getTargetKindOptions()
  return opts.find((o) => o.value === value)?.label ?? opts[0].label
}

export function formatTargetKindShort(value: string | null | undefined): string {
  if (value === 'library') return t('kind.libraryShort')
  if (value === 'mixed') return t('kind.mixedShort')
  return t('kind.webShort')
}

export function formatVulnProjectName(name: string, kind?: string | null): string {
  const label = (name || '').trim() || t('project.fallback')
  return t('project.namedKind', { name: label, kind: formatTargetKindShort(kind) })
}

export function formatTargetKindHint(value: string | null | undefined): string {
  const opts = getTargetKindOptions()
  return opts.find((o) => o.value === value)?.hint ?? opts[0].hint
}

export function normalizeTargetKind(value: string | null | undefined): TargetKind {
  if (value === 'library' || value === 'mixed') return value
  return 'web'
}

export function getBountyScopeRows() {
  return [
    { type: 'RCE', included: true, note: t('bounty.rce') },
    { type: 'SSTI', included: true, note: '' },
    { type: t('bounty.row.deser'), included: true, note: '' },
    { type: t('bounty.row.sqli'), included: true, note: '' },
    { type: t('bounty.row.xml'), included: true, note: '' },
    { type: t('bounty.row.fileops'), included: true, note: t('bounty.fileops') },
    { type: t('bounty.row.upload'), included: true, note: '' },
    { type: t('bounty.row.lfi'), included: true, note: '' },
    { type: t('bounty.row.ssrfIn'), included: true, note: t('bounty.ssrfIn') },
    { type: t('bounty.row.leak'), included: true, note: '' },
    { type: t('bounty.row.auth'), included: true, note: '' },
    { type: t('bounty.row.idor'), included: true, note: '' },
    { type: 'DoS', included: true, note: '' },
    { type: t('bounty.row.storedXss'), included: true, note: t('bounty.xss') },
    { type: t('bounty.row.csrf'), included: true, note: t('bounty.csrf') },
    { type: t('bounty.row.secret'), included: true, note: t('bounty.secret') },
    { type: t('bounty.row.other'), included: true, note: t('bounty.other') },
    { type: t('bounty.row.ssrfOut'), included: false, note: t('bounty.ssrfOut') },
    { type: t('bounty.row.rxss'), included: false, note: '' },
    { type: t('bounty.row.csrfLow'), included: false, note: t('bounty.csrfLow') },
    { type: t('bounty.row.cors'), included: false, note: t('bounty.cors') },
    { type: t('bounty.row.redirect'), included: false, note: t('bounty.redirect') },
    { type: t('bounty.row.rate'), included: false, note: t('bounty.rate') },
    { type: t('bounty.row.prng'), included: false, note: t('bounty.token') },
    { type: t('bounty.row.aes'), included: false, note: t('bounty.aes') },
    { type: t('bounty.row.passwd'), included: false, note: t('bounty.passwd') },
    { type: t('bounty.row.hardening'), included: false, note: t('bounty.hardening') },
  ] as const
}

/** @deprecated use getBountyScopeRows() */
export const BOUNTY_SCOPE_ROWS = getBountyScopeRows()

export function getBountyScopePremise() {
  return t('bounty.premise')
}

export const BOUNTY_SCOPE_PREMISE = getBountyScopePremise()

export function formatAuditMode(
  value: string | null | undefined,
  customName?: string | null,
): string {
  if (value === 'custom') {
    const name = (customName || '').trim()
    return name ? t('audit.customNamed', { name }) : t('audit.custom')
  }
  const opts = getAuditModeOptions()
  return opts.find((o) => o.value === value)?.label ?? opts[0].label
}

export function formatAuditModeHint(
  value: string | null | undefined,
  customName?: string | null,
): string {
  const opts = getAuditModeOptions()
  if (value === 'custom') {
    const name = (customName || '').trim()
    return name ? t('audit.customActiveHint', { name }) : opts.find((o) => o.value === 'custom')!.hint
  }
  return opts.find((o) => o.value === value)?.hint ?? opts[0].hint
}

export function projectRunBucket(
  status: string | null | undefined,
  projectPaused?: boolean,
): 'running' | 'paused' | 'completed' | 'stopped' {
  if (status === 'completed') return 'completed'
  if (status === 'paused' || projectPaused) return 'paused'
  if (status === 'cancelled' || status === 'error') return 'stopped'
  return 'running'
}

export function formatProjectRunStatus(
  status: string | null | undefined,
  projectPaused?: boolean,
): string {
  const bucket = projectRunBucket(status, projectPaused)
  if (bucket === 'completed') return t('run.completed')
  if (bucket === 'paused') return t('run.paused')
  if (bucket === 'stopped') return t('run.stopped')
  return t('run.running')
}

export function formatProjectStatus(status: string | null | undefined): string {
  switch (status) {
    case 'pending':
      return t('projStatus.pending')
    case 'ingesting':
      return t('projStatus.ingesting')
    case 'recon':
      return t('projStatus.recon')
    case 'auditing':
      return t('projStatus.auditing')
    case 'reviewing':
      return t('projStatus.reviewing')
    case 'paused':
      return t('projStatus.paused')
    case 'completed':
      return t('projStatus.completed')
    case 'cancelled':
      return t('projStatus.cancelled')
    case 'error':
      return t('projStatus.error')
    default:
      return status?.trim() || t('common.dash')
  }
}

export function projectStatusBadgeVariant(
  status: string | null | undefined,
  projectPaused?: boolean,
): 'info' | 'success' | 'warning' | 'destructive' {
  const bucket = projectRunBucket(status, projectPaused)
  if (bucket === 'completed') return 'success'
  if (bucket === 'paused') return 'warning'
  if (bucket === 'stopped') return 'destructive'
  return 'info'
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('common.dash')
  let s = value.trim()
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s) && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(s)) {
    s = `${s.replace(' ', 'T')}Z`
  }
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return value
  return d.toLocaleString(dateLocale(getLocale()), { timeZone: 'Asia/Shanghai' })
}

export const VULN_TYPE_IDS = [
  'rce',
  'ssti',
  'deserialization',
  'jndi_injection',
  'jdbc_attack',
  'file_read',
  'file_upload',
  'file_delete',
  'auth_bypass',
  'sqli',
  'xxe',
  'path_traversal',
  'ssrf',
  'privilege_escalation',
  'dos',
  'xss',
  'stored_xss',
  'csrf',
  'hardcoded_secret',
  'info_disclosure',
  'other',
] as const

const VULN_TYPE_FIXED: Record<string, string> = {
  rce: 'RCE',
  ssti: 'SSTI',
  xxe: 'XXE',
  ssrf: 'SSRF',
  dos: 'DoS',
  xss: 'XSS',
  csrf: 'CSRF',
}

export function getVulnTypeOptions(): [string, string][] {
  return VULN_TYPE_IDS.map((id) => {
    if (VULN_TYPE_FIXED[id]) return [id, VULN_TYPE_FIXED[id]]
    return [id, t(`vulnType.${id}`)]
  })
}

/** @deprecated use getVulnTypeOptions() */
export const VULN_TYPE_OPTIONS = getVulnTypeOptions()

export function formatVulnType(value: string | null | undefined): string {
  const key = (value || '').trim()
  if (!key) return ''
  const hit = getVulnTypeOptions().find(([id]) => id === key)
  return hit ? hit[1] : key
}

export function formatSeverity(value: string | null | undefined): string {
  switch (value) {
    case 'critical':
      return t('severity.critical')
    case 'high':
      return t('severity.high')
    case 'medium':
      return t('severity.medium')
    case 'low':
      return t('severity.low')
    case 'pending':
      return t('severity.pending')
    case 'none':
      return t('severity.none')
    default:
      return value || ''
  }
}

export function formatSeverityScore(
  value: number | null | undefined,
  severity?: string | null,
  cvssVector?: string | null,
): string | null {
  if (value == null || Number.isNaN(value)) return null
  const label = formatSeverity(severity)
  if (cvssVector) {
    const n = Number(value).toFixed(1)
    return label ? `${n} ${label}` : n
  }
  const signed = value > 0 ? `+${value}` : String(value)
  return label ? `${label}${signed}` : signed
}

export function severityScoreBadgeClass(
  value: number | null | undefined,
  cvssVector?: string | null,
): string {
  if (value == null || Number.isNaN(value)) return ''
  if (cvssVector) {
    if (value >= 9) return 'bg-red-500/20 text-red-100 ring-1 ring-red-500/30'
    if (value >= 7) return 'bg-orange-500/20 text-orange-100 ring-1 ring-orange-500/30'
    if (value >= 4) return 'bg-amber-500/15 text-amber-100 ring-1 ring-amber-500/25'
    return 'bg-slate-500/15 text-slate-200 ring-1 ring-slate-500/20'
  }
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
  return t('progress.files', {
    audited: p.files_audited ?? 0,
    weighted: p.files_weighted ?? 0,
    skipped: p.files_skipped ?? 0,
    total: p.files_total ?? 0,
  })
}

export function formatSinkProgress(p: {
  sinks_done?: number | null
  sinks_queued?: number | null
}): string {
  return t('progress.sinks', { done: p.sinks_done ?? 0, queued: p.sinks_queued ?? 0 })
}

export function formatBypassProgress(p: {
  bypass_done?: number | null
  bypass_queued?: number | null
}): string {
  return t('progress.bypass', { done: p.bypass_done ?? 0, queued: p.bypass_queued ?? 0 })
}

export function formatMiningPaths(p: {
  heuristic_enabled?: boolean | null
  heuristic_lite?: boolean | null
  fast_enabled?: boolean | null
  bypass_enabled?: boolean | null
  unconstrained_enabled?: boolean | null
}): string {
  const heuristicOn = p.heuristic_enabled !== false
  const liteOn = heuristicOn && p.heuristic_lite === true
  const fastOn = p.fast_enabled === true
  const bypassOn = p.bypass_enabled === true
  const unconstrainedOn = p.unconstrained_enabled === true
  const parts: string[] = []
  if (heuristicOn) parts.push(liteOn ? t('mining.heuristicLite') : t('mining.heuristic'))
  if (fastOn) parts.push(t('mining.fast'))
  if (bypassOn) parts.push(t('mining.bypass'))
  if (unconstrainedOn) parts.push(t('mining.unconstrained'))
  return parts.join(' + ') || t('mining.heuristic')
}

export function formatMiningProgress(p: {
  heuristic_enabled?: boolean | null
  heuristic_lite?: boolean | null
  fast_enabled?: boolean | null
  bypass_enabled?: boolean | null
  unconstrained_enabled?: boolean | null
  unconstrained_done?: boolean | null
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
  const unconstrainedOn = p.unconstrained_enabled === true
  const parts: string[] = []
  if (heuristicOn && liteOn) {
    parts.push(t('progress.lite', { done: p.files_weight100_audited ?? 0, total: p.files_weight100 ?? 0 }))
  } else if (heuristicOn) {
    parts.push(formatFileProgress(p))
  }
  if (fastOn) parts.push(formatSinkProgress(p))
  if (bypassOn) parts.push(formatBypassProgress(p))
  if (unconstrainedOn) {
    parts.push(p.unconstrained_done ? t('progress.unconstrainedDone') : t('mining.unconstrained'))
  }
  return parts.join(' · ')
}

export function formatTokens(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return t('common.dash')
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
  if (i <= 0) return t('common.dash')
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
  const used = t('tokens.usage', {
    input: formatTokens(input),
    output: formatTokens(output),
    cache: formatCacheRate(cached, input),
  })
  if (cap > 0) return t('tokens.usageCap', { used, cap: formatTokens(cap) })
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
  if (bytes == null || Number.isNaN(Number(bytes))) return t('common.dash')
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
