import type { Vuln } from '../api'
import { t } from '@/i18n/t'
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

function miningTooltip(path: string): string {
  switch (path) {
    case 'heuristic':
      return t('mining.tip.heuristic')
    case 'fast':
      return t('mining.tip.fast')
    case 'bypass':
      return t('mining.tip.bypass')
    case 'unconstrained':
      return t('mining.tip.unconstrained')
    default:
      return formatMiningPath(path) || ''
  }
}

function miningListLabel(path: string | null | undefined): string {
  switch ((path || '').trim().toLowerCase()) {
    case 'heuristic':
      return t('mining.heuristicShort')
    case 'fast':
      return t('mining.fast')
    case 'bypass':
      return t('mining.bypass')
    case 'unconstrained':
      return t('mining.unconstrained')
    default:
      return formatMiningPath(path) || ''
  }
}

function formatSubmissionTierShort(value: string | null | undefined): string {
  switch (value) {
    case 'cve_candidate':
      return t('tier.cve')
    case 'low_impact':
      return t('tier.lowShort')
    case 'duplicate_grouped':
      return t('tier.dupShort')
    default:
      return formatSubmissionTier(value)
  }
}

/** Secondary inline tags — muted text, each with optional tooltip. */
export function vulnListSecondaryTags(v: Vuln, nested?: boolean): VulnListTag[] {
  const tags: VulnListTag[] = []

  if (nested) {
    tags.push({ label: t('tier.child'), tooltip: t('tier.childTip') })
  }

  const tierLabel = formatSubmissionTierShort(v.submission_tier)
  if (tierLabel && v.submission_tier) {
    tags.push({
      label: tierLabel,
      tooltip: v.submission_reason?.trim() || t('tier.reasonFallback', { label: formatSubmissionTier(v.submission_tier) }),
    })
  }

  const mining = miningListLabel(v.mining_path)
  if (mining) {
    const key = (v.mining_path || '').trim().toLowerCase()
    tags.push({ label: mining, tooltip: miningTooltip(key) || mining })
  }

  if (v.config_premise === 'specific') {
    const premise = formatConfigPremise(v.config_premise)
    if (premise) {
      tags.push({ label: premise, tooltip: t('config.tip.specific') })
    }
  }

  if (v.tracking_status === 'submitted' || v.tracking_status === 'ignored') {
    tags.push({
      label: formatTrackingStatus(v.tracking_status),
      tooltip: v.tracking_status === 'submitted' ? t('track.tip.submitted') : t('track.tip.ignored'),
    })
  }

  const verifier = formatVerifierStatus(v.verifier_status)
  if (verifier) {
    tags.push({ label: verifier, tooltip: t('verifier.tip') })
  }

  return tags
}

/** Full attribute list for the ··· hover panel — nothing omitted from list view. */
export function vulnListAttributeLines(v: Vuln, projectName?: string): VulnListAttributeLine[] {
  const lines: VulnListAttributeLine[] = [
    { label: t('attr.status'), value: formatVulnStatus(v.status, v.evidence_level, v.fp_kind, v.harness_depth) },
    {
      label: t('attr.severity'),
      value: formatSeverityScore(v.severity_score, v.severity, v.cvss_vector) || formatSeverity(v.severity) || t('common.dash'),
    },
    { label: t('attr.tier'), value: formatSubmissionTier(v.submission_tier) },
    {
      label: t('attr.project'),
      value: projectName ? t('project.refNamed', { id: v.project_id, name: projectName }) : t('project.ref', { id: v.project_id }),
    },
    { label: t('attr.type'), value: v.vuln_type || t('common.dash') },
  ]

  const surface = formatAttackSurface(v.attack_surface, v.required_account)
  if (surface) lines.push({ label: t('attr.priv'), value: surface })

  const exposure = formatExposureMode(v.exposure_mode)
  if (exposure) {
    lines.push({
      label: t('attr.exposure'),
      value: exposure + (v.upstream_chain_proven ? t('exposure.chainProven') : ''),
    })
  }

  const mining = formatMiningPath(v.mining_path)
  if (mining) lines.push({ label: t('attr.mining'), value: mining })

  const premise = formatConfigPremise(v.config_premise)
  if (premise) lines.push({ label: t('attr.premise'), value: premise })

  const evidence = formatEvidenceLevel(v.evidence_level, v.harness_depth)
  if (evidence) lines.push({ label: t('attr.evidence'), value: evidence })

  lines.push({ label: t('attr.tracking'), value: formatTrackingStatus(v.tracking_status) })

  const verifier = formatVerifierStatus(v.verifier_status)
  if (verifier) lines.push({ label: t('attr.verifier'), value: verifier })

  if (v.cvss_vector) lines.push({ label: 'CVSS', value: v.cvss_vector })

  if (v.submission_reason?.trim()) {
    lines.push({ label: t('attr.reason'), value: v.submission_reason.trim() })
  }

  return lines
}

export { formatSubmissionTierShort }
