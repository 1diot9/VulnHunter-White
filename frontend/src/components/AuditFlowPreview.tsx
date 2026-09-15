import type { ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn, formatAuditMode, formatMiningPaths } from '@/lib/utils'
import { useI18n } from '@/i18n'
import type { MessageVars } from '@/i18n/t'

type Translate = (key: string, vars?: MessageVars) => string

function reconSteps(t: Translate) {
  return [
    { id: 'map', label: t('flow.preview.map'), hint: t('flow.branch.map') },
    { id: 'source_ext', label: t('flow.preview.ext'), hint: t('flow.branch.sourceExt') },
    { id: 'old_vulns', label: t('flow.preview.oldVulns'), hint: t('flow.branch.oldVulns') },
    { id: 'mark', label: t('flow.preview.mark'), hint: t('flow.branch.mark') },
  ]
}

type PreviewProps = {
  auditMode: 'bounty' | 'full' | 'custom'
  dynamicVerifyEnabled: boolean
  dynamicVerifyMode?: 'off' | 'lab' | 'harness'
  manualLab: boolean
  /** False on Docker Desktop — lab means manual target only. */
  dockerLabBuildEnabled?: boolean
  verifierEnabled: boolean
  attackChainEnabled?: boolean
  codeIntelEnabled?: boolean
  heuristicEnabled?: boolean
  heuristicLite?: boolean
  fastEnabled?: boolean
  bypassEnabled?: boolean
  unconstrainedEnabled?: boolean
  className?: string
}

type FlowNode = {
  id: string
  title: string
  tag?: string
  skipped?: boolean
  body: string
  hint: string
  chips: { id: string; label: string; hint: string }[]
}

function buildNodes(t: Translate, {
  auditMode,
  dynamicVerifyEnabled,
  dynamicVerifyMode,
  manualLab,
  dockerLabBuildEnabled = true,
  verifierEnabled,
  attackChainEnabled = false,
  codeIntelEnabled = false,
  heuristicEnabled = true,
  heuristicLite = false,
  fastEnabled = false,
  bypassEnabled = false,
  unconstrainedEnabled = false,
}: PreviewProps): FlowNode[] {
  const bounty = auditMode !== 'full'
  const verifyMode = dynamicVerifyMode || (dynamicVerifyEnabled ? 'lab' : 'off')
  const useManual = verifyMode === 'lab' && (manualLab || !dockerLabBuildEnabled)
  const labOn = verifyMode === 'lab'
  const harnessOn = verifyMode === 'harness'
  const labTag = !dockerLabBuildEnabled && labOn ? t('verify.manual') : labOn ? t('verify.lab') : harnessOn ? t('verify.harness') : t('flow.preview.tag.static')
  const heuristicOn = heuristicEnabled !== false
  const liteOn = heuristicOn && heuristicLite === true
  const fastOn = fastEnabled === true
  const bypassOn = bypassEnabled === true
  const unconstrainedOn = unconstrainedEnabled === true
  const scopeChip = bounty
    ? { id: 'scope', label: t('flow.preview.scope.high'), hint: t('flow.preview.scope.highHint') }
    : { id: 'scope', label: t('flow.preview.scope.low'), hint: t('flow.preview.scope.lowHint') }
  const unconstrainedScopeChip = {
    id: 'scope',
    label: t('flow.preview.scope.high'),
    hint: t('flow.preview.unconstScopeHint'),
  }

  const mines: FlowNode[] = []
  if (heuristicOn) {
    mines.push({
      id: 'heuristic',
      title: liteOn ? t('mining.heuristicLite') : t('flow.reports.mine'),
      tag: bounty ? t('flow.preview.tag.bounty') : t('flow.preview.tag.full'),
      body: liteOn
        ? bounty
          ? t('flow.preview.heuristicLiteBounty')
          : t('flow.preview.heuristicLiteFull')
        : bounty
          ? t('flow.preview.heuristicBounty')
          : t('flow.preview.heuristicFull'),
      hint: liteOn
        ? t('flow.preview.heuristicLiteHint')
        : t('flow.preview.heuristicHint'),
      chips: [scopeChip],
    })
  }
  if (fastOn) {
    mines.push({
      id: 'fast',
      title: t('mining.fast'),
      tag: bounty ? t('flow.preview.tag.bounty') : t('flow.preview.tag.full'),
      body: bounty
        ? t('flow.preview.fastBounty')
        : t('flow.preview.fastFull'),
      hint: t('flow.preview.fastHint'),
      chips: [scopeChip],
    })
  }
  if (bypassOn) {
    mines.push({
      id: 'bypass',
      title: t('mining.bypass'),
      tag: bounty ? t('flow.preview.tag.bounty') : t('flow.preview.tag.full'),
      body: bounty
        ? t('flow.preview.bypassBounty')
        : t('flow.preview.bypassFull'),
      hint: t('flow.preview.bypassHint'),
      chips: [scopeChip],
    })
  }
  if (unconstrainedOn) {
    mines.push({
      id: 'unconstrained',
      title: t('mining.unconstrained'),
      tag: t('flow.preview.tag.bounty'),
      body: t('flow.preview.unconstBody'),
      hint: t('flow.preview.unconstHint'),
      chips: [unconstrainedScopeChip],
    })
  }

  return [
    {
      id: 'recon',
      title: t('flow.phase.recon'),
      body: t('flow.preview.reconBody'),
      hint: t('flow.preview.reconHint'),
      chips: [...reconSteps(t)],
    },
    {
      id: 'code_intel',
      title: t('flow.phase.codeIntel'),
      tag: codeIntelEnabled ? 'CodeGraph' : t('flow.preview.ciOff'),
      skipped: !codeIntelEnabled,
      body: codeIntelEnabled
        ? t('flow.preview.ciOnBody')
        : t('flow.preview.ciOffBody'),
      hint: codeIntelEnabled
        ? t('flow.preview.ciOnHint')
        : t('flow.preview.ciOffHint'),
      chips: codeIntelEnabled
        ? [{ id: 'src', label: t('flow.preview.srcOnly'), hint: t('flow.preview.srcHint') }]
        : [],
    },
    ...mines,
    {
      id: 'reviewer',
      title: t('flow.phase.reviewer'),
      tag: labTag,
      body: labOn
        ? useManual
          ? dockerLabBuildEnabled
            ? t('flow.preview.reviewManualDocker')
            : t('flow.preview.reviewManualOnly')
          : t('flow.preview.reviewDocker')
        : harnessOn
          ? t('flow.preview.reviewHarness')
          : t('flow.preview.reviewStatic'),
      hint: labOn
        ? dockerLabBuildEnabled
          ? t('flow.preview.reviewLabHint')
          : t('flow.preview.reviewManualHint')
        : harnessOn
          ? t('flow.preview.reviewHarnessHint')
          : t('flow.preview.reviewStaticHint'),
      chips: labOn
        ? [
            {
              id: 'lab',
              label: useManual ? t('verify.manual') : t('flow.preview.labSetup'),
              hint: useManual
                ? dockerLabBuildEnabled
                  ? t('flow.preview.labManualPrefer')
                  : t('flow.preview.labManualOnly')
                : t('flow.branch.lab'),
            },
            {
              id: 'poc',
              label: 'HTTP / MCP',
              hint: t('flow.preview.pocHint'),
            },
          ]
        : harnessOn
          ? [
              {
                id: 'harness',
                label: t('flow.preview.sandbox'),
                hint: t('flow.preview.sandboxHint'),
              },
            ]
          : [],
    },
    {
      id: 'verifier',
      title: t('flow.phase.verifier'),
      tag: verifierEnabled ? 'FOFA' : t('flow.preview.ciOff'),
      skipped: !verifierEnabled,
      body: verifierEnabled
        ? t('flow.preview.verifyOn')
        : t('flow.preview.verifyOff'),
      hint: verifierEnabled
        ? t('flow.preview.verifyOnHint')
        : t('flow.preview.verifyOffHint'),
      chips: verifierEnabled
        ? [
            { id: 'frontend', label: t('flow.preview.chip.frontend'), hint: t('flow.preview.chip.frontendHint') },
            { id: 'three', label: t('flow.preview.chip.three'), hint: t('flow.preview.chip.threeHint') },
            { id: 'skip', label: t('flow.preview.chip.skip'), hint: t('flow.preview.chip.skipHint') },
          ]
        : [],
    },
    {
      id: 'attack_chain',
      title: t('flow.phase.attackChain'),
      tag: attackChainEnabled ? t('flow.preview.chainTag') : t('flow.preview.ciOff'),
      skipped: !attackChainEnabled,
      body: attackChainEnabled
        ? t('flow.preview.chainOn')
        : t('flow.preview.chainOff'),
      hint: attackChainEnabled
        ? t('flow.preview.chainOnHint')
        : t('flow.preview.chainOffHint'),
      chips: attackChainEnabled
        ? [
            { id: 'confirmed', label: t('flow.preview.chip.confirmed'), hint: t('flow.preview.chip.confirmedHint') },
            { id: 'min2', label: t('flow.preview.chip.min2'), hint: t('flow.preview.chip.min2Hint') },
          ]
        : [],
    },
    {
      id: 'done',
      title: t('flow.phase.done'),
      body:
        verifierEnabled || attackChainEnabled
          ? t('flow.preview.donePost')
          : t('flow.preview.doneOnly'),
      hint: t('flow.preview.doneHint'),
      chips: [],
    },
  ]
}

function FlowTip({ hint, children }: { hint: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger render={<span className="inline-flex max-w-full cursor-default" />}>
        {children}
      </TooltipTrigger>
      <TooltipContent side="top" className="text-left leading-relaxed whitespace-normal">
        {hint}
      </TooltipContent>
    </Tooltip>
  )
}

function FlowBox({ node }: { node: FlowNode }) {
  return (
    <div
      className={cn(
        'flex h-full w-full flex-col rounded-lg border px-3 py-2.5 transition-colors',
        node.skipped
          ? 'border-dashed border-border/80 bg-transparent'
          : 'border-blue-500/35 bg-blue-500/10',
      )}
    >
      <FlowTip hint={node.hint}>
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium">{node.title}</span>
          {node.tag ? (
            <Badge variant={node.skipped ? 'outline' : 'info'} className="h-4 px-1.5 text-[10px]">
              {node.tag}
            </Badge>
          ) : null}
        </div>
      </FlowTip>
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{node.body}</p>
      {node.chips.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {node.chips.map((chip) => (
            <FlowTip key={chip.id} hint={chip.hint}>
              <Badge variant="outline">{chip.label}</Badge>
            </FlowTip>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function FlowConnector({ down, back }: { down?: string; back?: string }) {
  if (down || back) {
    return (
      <div className="grid h-9 grid-cols-[1fr_auto_1fr] items-center" aria-hidden>
        <span className="pr-2 text-right text-[10px] text-slate-500">{down ? `${down} ↓` : ''}</span>
        <div className="h-full w-px bg-slate-600" />
        <span className="pl-2 text-[10px] text-slate-500">{back ? `← ${back}` : ''}</span>
      </div>
    )
  }
  return (
    <div className="relative flex h-7 items-center justify-center" aria-hidden>
      <div className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-slate-600" />
      <span className="relative z-[1] translate-y-1.5 text-[9px] leading-none text-slate-500">▼</span>
    </div>
  )
}

function FlowFork({ nodes }: { nodes: FlowNode[] }) {
  if (nodes.length === 0) return null
  if (nodes.length === 1) {
    return (
      <div>
        <FlowConnector />
        <FlowBox node={nodes[0]} />
      </div>
    )
  }
  return (
    <div>
      <div className="mx-auto h-3 w-px bg-slate-600" aria-hidden />
      <div
        className={cn(
          'relative grid gap-2',
          nodes.length >= 4 ? 'grid-cols-2' : nodes.length >= 3 ? 'grid-cols-3' : 'grid-cols-2',
        )}
      >
        <div
          className={cn(
            'pointer-events-none absolute top-0 h-px bg-slate-600',
            nodes.length >= 4 ? 'left-1/4 right-1/4' : nodes.length >= 3 ? 'left-[16.67%] right-[16.67%]' : 'left-1/4 right-1/4',
          )}
          aria-hidden
        />
        {nodes.map((node) => (
          <div key={node.id} className="flex min-w-0 flex-col items-center">
            <div className="h-3 w-px shrink-0 bg-slate-600" aria-hidden />
            <div className="w-full">
              <FlowBox node={node} />
            </div>
            <div className="min-h-3 w-px flex-1 bg-slate-600" aria-hidden />
          </div>
        ))}
        <div
          className={cn(
            'pointer-events-none absolute bottom-0 h-px bg-slate-600',
            nodes.length >= 4 ? 'left-1/4 right-1/4' : nodes.length >= 3 ? 'left-[16.67%] right-[16.67%]' : 'left-1/4 right-1/4',
          )}
          aria-hidden
        />
      </div>
    </div>
  )
}

function isMineNode(id: string) {
  return id === 'heuristic' || id === 'fast' || id === 'bypass' || id === 'unconstrained'
}

function summaryText(t: Translate, {
  auditMode,
  dynamicVerifyEnabled,
  dynamicVerifyMode,
  manualLab,
  dockerLabBuildEnabled = true,
  verifierEnabled,
  attackChainEnabled = false,
  codeIntelEnabled = false,
  heuristicEnabled = true,
  heuristicLite = false,
  fastEnabled = false,
  bypassEnabled = false,
  unconstrainedEnabled = false,
}: PreviewProps): string {
  const mode = formatAuditMode(auditMode)
  const paths = formatMiningPaths({
    heuristic_enabled: heuristicEnabled,
    heuristic_lite: heuristicLite,
    fast_enabled: fastEnabled,
    bypass_enabled: bypassEnabled,
    unconstrained_enabled: unconstrainedEnabled,
  })
  const onCount =
    (heuristicEnabled !== false ? 1 : 0) +
    (fastEnabled === true ? 1 : 0) +
    (bypassEnabled === true ? 1 : 0) +
    (unconstrainedEnabled === true ? 1 : 0)
  const mine = onCount > 1 ? `${mode} · ${paths.replaceAll(' + ', ' ∥ ')}` : `${mode} · ${paths}`
  const verifyMode = dynamicVerifyMode || (dynamicVerifyEnabled ? 'lab' : 'off')
  const review =
    verifyMode === 'lab'
      ? !dockerLabBuildEnabled || manualLab
        ? dockerLabBuildEnabled
          ? t('flow.preview.reviewLabManualFirst')
          : t('verify.manual')
        : t('verify.lab')
      : verifyMode === 'harness'
        ? t('verify.harness')
        : t('flow.preview.reviewStaticReview')
  const post: string[] = []
  if (verifierEnabled) post.push(t('flow.preview.internetVerify'))
  if (attackChainEnabled) post.push(t('flow.phase.attackChain'))
  const tail = post.length > 0 ? t('flow.preview.tail', { post: post.join(' ∥ ') }) : t('flow.phase.done')
  const head = codeIntelEnabled ? t('flow.preview.headBoth') : t('flow.phase.recon')
  return t('flow.preview.summaryLine', { head, mine, review, tail })
}

export function AuditFlowPreview(props: PreviewProps) {
  const { t } = useI18n()
  const nodes = buildNodes(t, props)
  const summary = summaryText(t, props)
  const recon = nodes.find((n) => n.id === 'recon')
  const codeIntel = nodes.find((n) => n.id === 'code_intel')
  const mines = nodes.filter((n) => isMineNode(n.id))
  const rest = nodes.filter((n) => n.id !== 'recon' && n.id !== 'code_intel' && !isMineNode(n.id))
  const startStages = [recon, codeIntel].filter((n): n is FlowNode => Boolean(n))

  return (
    <TooltipProvider delay={200}>
      <section
        className={cn('rounded-xl bg-muted/25 p-3 ring-1 ring-foreground/10', props.className)}
        aria-label={t('flow.preview.aria')}
      >
        <h2 className="text-xs font-medium text-muted-foreground">{t('flow.preview.title')}</h2>
        <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{summary}</p>
        <div className="mt-3">
          <div className="grid grid-cols-2 items-stretch gap-2">
            {startStages.map((node) => (
              <FlowBox key={node.id} node={node} />
            ))}
          </div>
          <FlowFork nodes={mines} />
          {rest.map((node) => (
            <div key={node.id}>
              {node.id === 'reviewer' ? (
                <FlowConnector down={t('flow.preview.submit')} back={t('flow.preview.debt')} />
              ) : node.id === 'verifier' && node.skipped ? (
                <FlowConnector down={t('flow.preview.skip')} />
              ) : (
                <FlowConnector />
              )}
              <FlowBox node={node} />
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
          {t('flow.preview.footer')}
        </p>
      </section>
    </TooltipProvider>
  )
}
