import type { Vuln } from '../api'
import {
  formatAttackSurface,
  formatConfigPremise,
  formatEvidenceLevel,
  formatExposureMode,
  formatMiningPath,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
  formatTrackingStatus,
  formatVerifierStatus,
  formatVulnStatus,
} from './utils'

export type VulnListTag = {
  label: string
  tooltip?: string | null
}

export type VulnListAttributeLine = {
  label: string
  value: string
}

const MINING_TOOLTIPS: Record<string, string> = {
  heuristic: '由启发式 Worker 在 Recon 完成后按文件挖掘产出。',
  fast: '由快速扫描路径（Semgrep → SinkTriage → Fast Worker）产出。',
  bypass: '由历史漏洞绕过路径尝试补丁绕过或未修复确认产出。',
  unconstrained: '由无约束扫描路径产出。该路径始终走赏金闸门；Reviewer 可判定是否达成 RCE 效果。',
}

const CONFIG_TOOLTIPS: Record<string, string> = {
  default: '默认/官方部署配置下即可触发或利用。',
  specific: '须修改应用自身配置选项后才可触发；不含官方已警示的风险开关。',
}

function formatSubmissionTierShort(value: string | null | undefined): string {
  switch (value) {
    case 'cve_candidate':
      return '有 CVE 价值'
    case 'low_impact':
      return '低危害'
    case 'duplicate_grouped':
      return '同根因'
    default:
      return formatSubmissionTier(value)
  }
}

/** Secondary inline tags — muted text, each with optional tooltip. */
export function vulnListSecondaryTags(v: Vuln, nested?: boolean): VulnListTag[] {
  const tags: VulnListTag[] = []

  if (nested) {
    tags.push({ label: '子项', tooltip: '同根因合并组内的子报告，详情见主报告或展开项。' })
  }

  const tierLabel = formatSubmissionTierShort(v.submission_tier)
  if (tierLabel && v.submission_tier) {
    tags.push({
      label: tierLabel,
      tooltip:
        v.submission_reason?.trim() ||
        `${formatSubmissionTier(v.submission_tier)}：Reviewer 确认时的价值分层。`,
    })
  }

  const mining = formatMiningPath(v.mining_path)
  if (mining) {
    const key = (v.mining_path || '').trim().toLowerCase()
    tags.push({ label: mining.replace('挖掘', ''), tooltip: MINING_TOOLTIPS[key] || mining })
  }

  if (v.config_premise === 'specific') {
    const premise = formatConfigPremise(v.config_premise)
    if (premise) {
      tags.push({ label: premise, tooltip: CONFIG_TOOLTIPS.specific })
    }
  }

  if (v.tracking_status === 'submitted' || v.tracking_status === 'ignored') {
    tags.push({
      label: formatTrackingStatus(v.tracking_status),
      tooltip: v.tracking_status === 'submitted' ? '你已标记为已向外提交。' : '你已标记为忽略，不再跟进提交。',
    })
  }

  const verifier = formatVerifierStatus(v.verifier_status)
  if (verifier) {
    tags.push({ label: verifier, tooltip: 'Verifier 互联网复测状态。完整目标列表见漏洞详情。' })
  }

  return tags
}

/** Full attribute list for the ··· hover panel — nothing omitted from list view. */
export function vulnListAttributeLines(v: Vuln, projectName?: string): VulnListAttributeLine[] {
  const lines: VulnListAttributeLine[] = [
    { label: '状态', value: formatVulnStatus(v.status, v.evidence_level, v.fp_kind, v.harness_depth) },
    {
      label: '严重度',
      value: formatSeverityScore(v.severity_score, v.severity, v.cvss_vector) || formatSeverity(v.severity) || '—',
    },
    { label: '价值分层', value: formatSubmissionTier(v.submission_tier) },
    { label: '项目', value: projectName ? `#${v.project_id} ${projectName}` : `#${v.project_id}` },
    { label: '类型', value: v.vuln_type || '—' },
  ]

  const surface = formatAttackSurface(v.attack_surface, v.required_account)
  if (surface) lines.push({ label: '权限要求', value: surface })

  const exposure = formatExposureMode(v.exposure_mode)
  if (exposure) {
    lines.push({
      label: '暴露模式',
      value: exposure + (v.upstream_chain_proven ? '（上游链已证）' : ''),
    })
  }

  const mining = formatMiningPath(v.mining_path)
  if (mining) lines.push({ label: '挖掘路径', value: mining })

  const premise = formatConfigPremise(v.config_premise)
  if (premise) lines.push({ label: '配置前提', value: premise })

  const evidence = formatEvidenceLevel(v.evidence_level, v.harness_depth)
  if (evidence) lines.push({ label: '验证方式', value: evidence })

  lines.push({ label: '提交跟踪', value: formatTrackingStatus(v.tracking_status) })

  const verifier = formatVerifierStatus(v.verifier_status)
  if (verifier) lines.push({ label: '互联网验证', value: verifier })

  if (v.cvss_vector) lines.push({ label: 'CVSS', value: v.cvss_vector })

  if (v.submission_reason?.trim()) {
    lines.push({ label: '分层理由', value: v.submission_reason.trim() })
  }

  return lines
}

export { formatSubmissionTierShort }
