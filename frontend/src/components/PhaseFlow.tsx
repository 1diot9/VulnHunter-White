import { Fragment, type ReactElement, type ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useI18n } from '@/i18n'
import type { MessageVars } from '@/i18n/t'

type Translate = (key: string, vars?: MessageVars) => string

const PHASE_IDS = ['recon', 'code_intel', 'worker', 'reviewer', 'verifier', 'attack_chain', 'done'] as const
type PhaseId = (typeof PHASE_IDS)[number]

function flowPhases(t: Translate) {
  return [
    { id: 'recon' as const, label: t('flow.phase.recon'), hint: t('flow.phase.reconHint') },
    { id: 'code_intel' as const, label: t('flow.phase.codeIntel'), hint: t('flow.phase.codeIntelHint') },
    { id: 'worker' as const, label: t('flow.phase.worker'), hint: t('flow.phase.workerHint') },
    { id: 'reviewer' as const, label: t('flow.phase.reviewer'), hint: t('flow.phase.reviewerHint') },
    { id: 'verifier' as const, label: t('flow.phase.verifier'), hint: t('flow.phase.verifierHint') },
    { id: 'attack_chain' as const, label: t('flow.phase.attackChain'), hint: t('flow.phase.attackChainHint') },
    { id: 'done' as const, label: t('flow.phase.done'), hint: t('flow.phase.doneHint') },
  ]
}

function branchHints(t: Translate): Record<string, string> {
  return {
    map: t('flow.branch.map'),
    source_ext: t('flow.branch.sourceExt'),
    old_vulns: t('flow.branch.oldVulns'),
    mark: t('flow.branch.mark'),
    lab: t('flow.branch.lab'),
    manualLab: t('flow.branch.manualLab'),
    harness: t('flow.branch.harness'),
  }
}

type Tone = 'neutral' | 'success' | 'info'

function badgeVariant(tone: Tone): 'outline' | 'success' | 'info' {
  if (tone === 'success') return 'success'
  if (tone === 'info') return 'info'
  return 'outline'
}

export type ReconSubphaseView = {
  id: string
  label: string
  done: boolean
}

type FlowState = {
  phase: string
  status: string
  reconDone: boolean
  codeIntelEnabled?: boolean
  codeIntelStatus?: string
  codeIntelDone?: boolean
  filesAudited?: number
  filesSkipped?: number
  filesTotal?: number
  filesWeight100?: number
  filesWeight100Audited?: number
  workerRounds?: number
  vulnPending?: number
  reconSubphases?: ReconSubphaseView[]
  labSetupDone?: boolean
  manualLab?: boolean
  dynamicVerifyEnabled?: boolean
  dynamicVerifyMode?: 'off' | 'lab' | 'harness'
  verifierEnabled?: boolean
  verifierPending?: number
  attackChainEnabled?: boolean
  attackChainDone?: boolean
  attackChainStopped?: boolean
  heuristicEnabled?: boolean
  heuristicLite?: boolean
  fastEnabled?: boolean
  fastQueueFrozen?: boolean
  sinksQueued?: number
  sinksDone?: number
  bypassEnabled?: boolean
  bypassQueueFrozen?: boolean
  bypassQueued?: number
  bypassDone?: number
  unconstrainedEnabled?: boolean
  unconstrainedDone?: boolean
  heuristicStopped?: boolean
  fastStopped?: boolean
  bypassStopped?: boolean
}

type BranchItem = {
  id: string
  node: ReactNode
}

function miningPrereqs(s: FlowState): boolean {
  if (!s.reconDone) return false
  if (s.codeIntelEnabled === true) return Boolean(s.codeIntelDone)
  return true
}

function heuristicFinished(s: FlowState): boolean {
  if (s.heuristicEnabled === false) return true
  if (s.heuristicStopped === true) return true
  if (!miningPrereqs(s)) return false
  if (s.heuristicLite === true) {
    return (s.filesWeight100Audited ?? 0) >= (s.filesWeight100 ?? 0)
  }
  const total = s.filesTotal ?? 0
  if (total <= 0) return false
  return (s.filesAudited ?? 0) + (s.filesSkipped ?? 0) >= total
}

function fastFinished(s: FlowState): boolean {
  if (s.fastEnabled !== true) return true
  if (s.fastStopped === true) return true
  if (!miningPrereqs(s) || !s.fastQueueFrozen) return false
  return (s.sinksDone ?? 0) >= (s.sinksQueued ?? 0)
}

function bypassFinished(s: FlowState): boolean {
  if (s.bypassEnabled !== true) return true
  if (s.bypassStopped === true) return true
  if (!s.bypassQueueFrozen) return false
  return (s.bypassDone ?? 0) >= (s.bypassQueued ?? 0)
}

function unconstrainedFinished(s: FlowState): boolean {
  if (s.unconstrainedEnabled !== true) return true
  return s.unconstrainedDone === true
}

function workerFinished(s: FlowState): boolean {
  return heuristicFinished(s) && fastFinished(s) && bypassFinished(s) && unconstrainedFinished(s)
}

function heuristicTone(s: FlowState): Tone {
  if (s.heuristicEnabled === false) return 'neutral'
  if (heuristicFinished(s)) return 'success'
  if (s.phase === 'worker' || s.phase === 'fix' || s.status === 'auditing' || (miningPrereqs(s) && !heuristicFinished(s))) {
    return 'info'
  }
  return 'neutral'
}

function fastTone(s: FlowState): Tone {
  if (s.fastEnabled !== true) return 'neutral'
  if (fastFinished(s)) return 'success'
  if (miningPrereqs(s) && (s.phase === 'worker' || s.status === 'auditing' || !fastFinished(s))) return 'info'
  return 'neutral'
}

function bypassTone(s: FlowState): Tone {
  if (s.bypassEnabled !== true) return 'neutral'
  if (bypassFinished(s)) return 'success'
  if (s.phase === 'worker' || s.status === 'auditing' || s.bypassQueueFrozen || miningPrereqs(s)) return 'info'
  return 'neutral'
}

function unconstrainedTone(s: FlowState): Tone {
  if (s.unconstrainedEnabled !== true) return 'neutral'
  if (unconstrainedFinished(s)) return 'success'
  if (s.phase === 'worker' || s.status === 'auditing' || miningPrereqs(s)) return 'info'
  return 'neutral'
}

function phaseTone(id: string, s: FlowState): Tone {
  const completed = s.status === 'completed' || s.phase === 'done'
  if (completed) return 'success'

  const workerDone = workerFinished(s)
  if (id === 'recon') {
    if (s.reconDone) return 'success'
    if (s.phase === 'recon' || s.status === 'recon' || s.status === 'ingesting') return 'info'
    return 'neutral'
  }
  if (id === 'code_intel') {
    if (s.codeIntelEnabled !== true) return 'neutral'
    const st = s.codeIntelStatus || 'pending'
    if (st === 'ready' || st === 'stale' || st === 'degraded' || s.codeIntelDone) return 'success'
    if (st === 'skipped') return 'neutral'
    if (st === 'building' || s.phase === 'code_intel' || s.status === 'recon' || s.status === 'ingesting' || s.status === 'auditing') {
      if (st === 'pending' && s.status === 'completed') return 'neutral'
      if (st === 'building' || s.phase === 'code_intel' || s.status === 'recon' || s.status === 'ingesting') return 'info'
    }
    if (s.status === 'completed' || s.phase === 'done') return 'neutral'
    if (st === 'building') return 'info'
    if (s.status === 'recon' || s.status === 'ingesting' || s.status === 'auditing' || s.status === 'paused') return 'info'
    return 'neutral'
  }
  if (id === 'worker') {
    if (workerDone) return 'success'
    if (s.phase === 'worker' || s.phase === 'fix' || s.status === 'auditing' || (miningPrereqs(s) && !workerDone)) {
      return 'info'
    }
    return 'neutral'
  }
  if (id === 'reviewer') {
    const pending = s.vulnPending ?? 0
    const mode = s.dynamicVerifyMode || (s.dynamicVerifyEnabled ? 'lab' : 'off')
    const dynamicOn = mode !== 'off'
    const labOk = mode !== 'lab' || Boolean(s.labSetupDone)
    if (labOk && pending === 0 && (completed || workerDone)) return 'success'
    if (
      mode === 'lab' &&
      !s.labSetupDone &&
      s.status !== 'pending' &&
      s.status !== 'error' &&
      s.status !== 'cancelled'
    ) {
      return 'info'
    }
    if (pending > 0) return 'info'
    return 'neutral'
  }
  if (id === 'verifier') {
    if (!s.verifierEnabled) return 'neutral'
    if ((s.verifierPending ?? 0) === 0 && (s.status === 'completed' || s.phase === 'done')) return 'success'
    if (s.phase === 'verifier' || (s.verifierPending ?? 0) > 0) return 'info'
    return 'neutral'
  }
  if (id === 'attack_chain') {
    if (!s.attackChainEnabled) return 'neutral'
    if (s.attackChainDone || s.status === 'completed' || s.phase === 'done') return 'success'
    if (s.attackChainStopped) return 'neutral'
    if (s.phase === 'attack_chain' || s.phase === 'attack-chain') return 'info'
    return 'neutral'
  }
  return 'neutral'
}

function subphaseTone(item: ReconSubphaseView, all: ReconSubphaseView[], s: FlowState): Tone {
  if (item.done || s.reconDone) return 'success'
  if (s.status === 'completed' || s.phase === 'done') return 'neutral'
  const firstOpen = all.find((x) => !x.done)
  if (firstOpen?.id === item.id) return 'info'
  return 'neutral'
}

function FlowTip({
  hint,
  side = 'top',
  children,
  render,
}: {
  hint: string
  side?: 'top' | 'bottom' | 'left' | 'right'
  children: ReactNode
  render?: ReactElement
}) {
  return (
    <Tooltip>
      <TooltipTrigger render={render ?? <span className="inline-flex cursor-default" />}>
        {children}
      </TooltipTrigger>
      <TooltipContent side={side} className="text-left leading-relaxed whitespace-normal">
        {hint}
      </TooltipContent>
    </Tooltip>
  )
}

function PhaseBranch({ items }: { items?: BranchItem[] }) {
  if (!items?.length) return null
  return (
    <div className="mt-0.5">
      <div className="ml-2.5 h-1.5 border-l border-slate-600" />
      <ul>
        {items.map((item, index) => {
          const last = index === items.length - 1
          return (
            <li key={item.id} className="relative pl-5">
              <span
                className="pointer-events-none absolute left-2.5 top-0 border-l border-slate-600"
                style={{ height: last ? '50%' : '100%' }}
              />
              <span className="pointer-events-none absolute left-2.5 top-1/2 w-2.5 border-t border-slate-600" />
              <div className="py-0.5">{item.node}</div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export default function PhaseFlow({
  phase,
  status,
  reconDone,
  codeIntelEnabled,
  codeIntelStatus,
  codeIntelDone,
  filesAudited,
  filesSkipped,
  filesTotal,
  filesWeight100,
  filesWeight100Audited,
  workerRounds,
  vulnPending,
  reconSubphases,
  labSetupDone,
  manualLab,
  dynamicVerifyEnabled,
  dynamicVerifyMode,
  verifierEnabled,
  verifierPending,
  attackChainEnabled,
  attackChainDone,
  attackChainStopped,
  heuristicEnabled,
  heuristicLite,
  fastEnabled,
  fastQueueFrozen,
  sinksQueued,
  sinksDone,
  bypassEnabled,
  bypassQueueFrozen,
  bypassQueued,
  bypassDone,
  unconstrainedEnabled,
  unconstrainedDone,
  heuristicStopped,
  fastStopped,
  bypassStopped,
  onSelect,
}: FlowState & { onSelect?: (id: string) => void }) {
  const state: FlowState = {
    phase,
    status,
    reconDone,
    codeIntelEnabled,
    codeIntelStatus,
    codeIntelDone,
    filesAudited,
    filesSkipped,
    filesTotal,
    filesWeight100,
    filesWeight100Audited,
    workerRounds,
    vulnPending,
    reconSubphases,
    labSetupDone,
    manualLab,
    dynamicVerifyEnabled,
    dynamicVerifyMode,
    verifierEnabled,
    verifierPending,
    attackChainEnabled,
    attackChainDone,
    attackChainStopped,
    heuristicEnabled,
    heuristicLite,
    fastEnabled,
    fastQueueFrozen,
    sinksQueued,
    sinksDone,
    bypassEnabled,
    bypassQueueFrozen,
    bypassQueued,
    bypassDone,
    unconstrainedEnabled,
    unconstrainedDone,
    heuristicStopped,
    fastStopped,
    bypassStopped,
  }
  const { t } = useI18n()
  const PHASES = flowPhases(t)
  const BRANCH_HINTS = branchHints(t)
  const subs = reconSubphases ?? []

  function branchOf(id: string): BranchItem[] {
    if (id === 'recon') {
      return subs.map((item) => ({
        id: item.id,
        node: (
          <FlowTip hint={BRANCH_HINTS[item.id] || t('flow.branch.subphase', { label: item.label })} side="right">
            <Badge variant={badgeVariant(subphaseTone(item, subs, state))}>
              {item.label}
              {item.done ? ' ✓' : ''}
            </Badge>
          </FlowTip>
        ),
      }))
    }
    if (id === 'worker') {
      const items: BranchItem[] = []
      if (state.heuristicEnabled !== false) {
        const done = heuristicFinished(state)
        const lite = state.heuristicLite === true
        const rounds = workerRounds ?? 0
        items.push({
          id: 'mine',
          node: (
            <Badge variant={badgeVariant(heuristicTone(state))}>
              {lite ? t('mining.heuristicLite') : t('flow.reports.mine')}
              {t('flow.badge.rounds', { rounds })}
              {state.heuristicStopped ? t('flow.badge.paused') : done ? ' ✓' : ''}
            </Badge>
          ),
        })
      }
      if (state.fastEnabled === true) {
        const done = fastFinished(state)
        const queued = state.sinksQueued ?? 0
        const progressed = state.sinksDone ?? 0
        items.push({
          id: 'fast',
          node: (
            <Badge variant={badgeVariant(fastTone(state))}>
              {t('mining.fast')}
              {state.fastQueueFrozen ? ` ${progressed}/${queued}` : t('flow.badge.preparing')}
              {state.fastStopped ? t('flow.badge.paused') : done ? ' ✓' : ''}
            </Badge>
          ),
        })
      }
      if (state.bypassEnabled === true) {
        const done = bypassFinished(state)
        const queued = state.bypassQueued ?? 0
        const progressed = state.bypassDone ?? 0
        items.push({
          id: 'bypass',
          node: (
            <Badge variant={badgeVariant(bypassTone(state))}>
              {t('mining.bypass')}
              {state.bypassQueueFrozen ? ` ${progressed}/${queued}` : t('flow.badge.waitOldVulns')}
              {state.bypassStopped ? t('flow.badge.paused') : done ? ' ✓' : ''}
            </Badge>
          ),
        })
      }
      if (state.unconstrainedEnabled === true) {
        const done = unconstrainedFinished(state)
        items.push({
          id: 'unconstrained',
          node: (
            <Badge variant={badgeVariant(unconstrainedTone(state))}>
              {t('mining.unconstrained')}
              {done ? ' ✓' : ''}
            </Badge>
          ),
        })
      }
      return items
    }
    if (id === 'reviewer') {
      const mode = state.dynamicVerifyMode || (state.dynamicVerifyEnabled ? 'lab' : 'off')
      if (mode === 'harness') {
        return [
          {
            id: 'harness',
            node: (
              <FlowTip hint={BRANCH_HINTS.harness} side="right">
                <Badge variant="info">{t('verify.harness')}</Badge>
              </FlowTip>
            ),
          },
        ]
      }
      if (mode !== 'lab') return []
      return [
        {
          id: 'lab',
          node: (
            <FlowTip hint={BRANCH_HINTS.lab} side="right">
              <Badge
                variant={badgeVariant(
                  state.labSetupDone ? 'success' : phaseTone('reviewer', state) === 'info' ? 'info' : 'neutral',
                )}
              >
                {t('flow.badge.labSetup')}{state.labSetupDone ? ' ✓' : ''}
              </Badge>
            </FlowTip>
          ),
        },
        ...(state.manualLab
          ? [
              {
                id: 'manual-lab',
                node: (
                  <FlowTip hint={BRANCH_HINTS.manualLab} side="right">
                    <Badge variant="info">{t('verify.manual')}</Badge>
                  </FlowTip>
                ),
              },
            ]
          : []),
      ]
    }
    return []
  }

  const branches: Record<PhaseId, BranchItem[]> = {
    recon: branchOf('recon'),
    code_intel: [],
    worker: branchOf('worker'),
    reviewer: branchOf('reviewer'),
    verifier: branchOf('verifier'),
    attack_chain: branchOf('attack_chain'),
    done: branchOf('done'),
  }
  const workerPaths = branches.worker
  const workerHints: Record<string, string> = {
    mine: t('flow.hint.mine'),
    fast: t('flow.hint.fast'),
    bypass: t('flow.hint.bypass'),
    unconstrained: t('flow.hint.unconstrained'),
  }

  const codeIntel = PHASES.find((p) => p.id === 'code_intel')
  const ciOn = state.codeIntelEnabled === true
  const ciStatus = state.codeIntelStatus || 'pending'
  const ciLabel =
    !ciOn || ciStatus === 'skipped'
      ? t('flow.ci.off')
      : ciStatus === 'stale'
        ? t('flow.ci.stale')
        : ciStatus === 'degraded'
          ? t('flow.ci.degraded')
          : t('flow.ci.on')
  const ciDoneMark =
    ciOn && (ciStatus === 'ready' || ciStatus === 'stale' || ciStatus === 'degraded' || state.codeIntelDone)

  return (
    <TooltipProvider delay={200}>
      <div className="flex flex-nowrap items-start gap-2 overflow-x-auto">
        {PHASES.map((p, i) => {
          if (p.id === 'code_intel') return null
          const visibleAfter = PHASES.slice(i + 1).find((x) => x.id !== 'code_intel')
          return (
          <Fragment key={p.id}>
            <div className="shrink-0">
              {p.id === 'recon' ? (
                <div className="flex flex-col gap-1">
                  <div className="flex h-6 items-center">
                    <FlowTip
                      hint={p.hint}
                      render={
                        <Button
                          type="button"
                          variant="ghost"
                          size="xs"
                          onClick={() => onSelect?.('recon')}
                          className="h-auto rounded-md p-0"
                        />
                      }
                    >
                      <Badge variant={badgeVariant(phaseTone('recon', state))}>
                        {t('flow.phase.recon')}{state.reconDone ? ' ✓' : ''}
                      </Badge>
                    </FlowTip>
                  </div>
                  {codeIntel ? (
                    <div className="flex h-6 items-center">
                      <FlowTip
                        hint={codeIntel.hint}
                        render={
                          <Button
                            type="button"
                            variant="ghost"
                            size="xs"
                            onClick={() => onSelect?.('code-intel')}
                            className="h-auto rounded-md p-0"
                          />
                        }
                      >
                        <Badge variant={badgeVariant(phaseTone('code_intel', state))}>
                          {ciLabel}
                          {ciDoneMark ? ' ✓' : ''}
                        </Badge>
                      </FlowTip>
                    </div>
                  ) : null}
                </div>
              ) : p.id === 'worker' && workerPaths.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {workerPaths.map((item, index) => (
                    <div key={item.id} className={index === 0 ? 'flex h-6 items-center' : undefined}>
                      <FlowTip
                        hint={workerHints[item.id] || p.hint}
                        render={
                          <Button
                            type="button"
                            variant="ghost"
                            size="xs"
                            onClick={() => onSelect?.(item.id)}
                            className="h-auto rounded-md p-0"
                          />
                        }
                      >
                        {item.node}
                      </FlowTip>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex h-6 items-center">
                  <FlowTip
                    hint={p.hint}
                    render={
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        onClick={() => onSelect?.(p.id)}
                        className="h-auto rounded-md p-0"
                      />
                    }
                  >
                    <Badge variant={badgeVariant(phaseTone(p.id, state))}>
                      {p.label}
                      {p.id === 'reviewer' && (state.dynamicVerifyMode || (state.dynamicVerifyEnabled ? 'lab' : 'off')) === 'off' ? t('flow.badge.static') : ''}
                      {p.id === 'reviewer' && (state.dynamicVerifyMode || (state.dynamicVerifyEnabled ? 'lab' : 'off')) === 'harness' ? t('flow.badge.partial') : ''}
                      {p.id === 'verifier' && !state.verifierEnabled ? t('flow.badge.off') : ''}
                      {p.id === 'attack_chain' && !state.attackChainEnabled ? t('flow.badge.off') : ''}
                      {p.id === 'attack_chain' && state.attackChainEnabled && state.attackChainStopped ? t('flow.badge.pausedShort') : ''}
                    </Badge>
                  </FlowTip>
                </div>
              )}
              <PhaseBranch items={p.id === 'worker' ? [] : branches[p.id] ?? []} />
            </div>
            {visibleAfter ? (
              <span className="flex h-6 shrink-0 items-center text-slate-600">→</span>
            ) : null}
          </Fragment>
          )
        })}
      </div>
    </TooltipProvider>
  )
}
