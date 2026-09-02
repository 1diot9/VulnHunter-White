import { Fragment, type ReactElement, type ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'

const PHASES = [
  {
    id: 'recon',
    label: '侦察',
    hint: '摸清项目结构与鉴权，补齐源码扩展名、收录历史漏洞，并为文件定权，供后续挖掘使用。',
  },
  {
    id: 'code_intel',
    label: '代码库',
    hint: '可选。用 CodeGraph 给 src/ 建代码数据库，供 Worker / Reviewer 查调用关系。默认关闭以免占磁盘；开启后与侦察并列，都完成后才挖掘。失败则降级继续用 Read/Grep。',
  },
  {
    id: 'worker',
    label: '挖掘',
    hint: '侦察完成后按文件挖洞；若开启了代码库则同时等其构建结束。轻量版只注入权重 100 的入口。快速扫描按 Semgrep Sink 回推。历史漏洞绕过按文档逐条尝试绕过。无约束扫描只注入地图与鉴权、固定 1 个 Worker，Reviewer 判定前台 RCE 效果后结束。开启的路径都结束后才算挖掘完成。',
  },
  {
    id: 'reviewer',
    label: '审核',
    hint: '独立验证 Worker 提交的漏洞。默认仅静态复核；靶场动态先跑 HTTP PoC，局部验证用沙箱 harness。',
  },
  {
    id: 'verifier',
    label: '验证',
    hint: '可选。Reviewer 确认前台漏洞后，用 FOFA 搜同款目标；先理解报告和 PoC 的利用本质，优先跑原 PoC，没有可用 PoC 时按报告构造 payload。失效时同链调整再利用。默认每轮 10 个，成功 3 个即结束；不足则再搜下一轮，最多 5 轮 / 50 个目标。',
  },
  {
    id: 'attack_chain',
    label: '攻击链',
    hint: '可选。挖掘与审核结束后，根据已确认漏洞尝试多步串联利用以扩大危害；已确认洞少于 2 条时跳过。',
  },
  {
    id: 'done',
    label: '完成',
    hint: '侦察、挖掘、审核与（若开启）互联网验证 / 攻击链串联均已结束。',
  },
] as const

const BRANCH_HINTS: Record<string, string> = {
  map: '梳理模块、HTTP 与非 HTTP 入口和技术栈，并写出登录 / 角色 / 权限文档。',
  source_ext: '把默认未入库的执行面文件（模板、ORM 映射等）补进索引。',
  old_vulns: '先跑 GHSA 与 GitHub Issues 爬虫，由 Agent 按爬虫结果落盘；完成后再用 WebSearch 补漏。',
  mark: '按批次给源码定权或跳过，决定后续挖掘优先级。',
  lab: '用 Docker 搭建默认可复用靶场，供动态复现；不是制造利用条件。',
  manualLab: '使用用户提供的漏洞环境地址做动态验证，跳过 Docker 搭建。',
  harness: '抽出函数并 mock 依赖，在沙箱跑 harness；不搭整项目靶场。',
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
  if (!miningPrereqs(s) || !s.fastQueueFrozen) return false
  return (s.sinksDone ?? 0) >= (s.sinksQueued ?? 0)
}

function bypassFinished(s: FlowState): boolean {
  if (s.bypassEnabled !== true) return true
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
  }
  const subs = reconSubphases ?? []

  function branchOf(id: string): BranchItem[] {
    if (id === 'recon') {
      return subs.map((item) => ({
        id: item.id,
        node: (
          <FlowTip hint={BRANCH_HINTS[item.id] || `${item.label}子阶段`} side="right">
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
              {lite ? '启发式轻量' : '启发式'}
              {` ${rounds} 轮`}
              {done ? ' ✓' : ''}
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
              快速扫描
              {state.fastQueueFrozen ? ` ${progressed}/${queued}` : ' 准备中'}
              {done ? ' ✓' : ''}
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
              历史漏洞绕过
              {state.bypassQueueFrozen ? ` ${progressed}/${queued}` : ' 等待历史漏洞'}
              {done ? ' ✓' : ''}
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
              无约束扫描
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
                <Badge variant="info">局部验证</Badge>
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
                环境搭建{state.labSetupDone ? ' ✓' : ''}
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
                    <Badge variant="info">人工靶场</Badge>
                  </FlowTip>
                ),
              },
            ]
          : []),
      ]
    }
    return []
  }

  const branches: Record<(typeof PHASES)[number]['id'], BranchItem[]> = {
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
    mine: '侦察完成后按文件定权：入口正向挖，更低权按角色回推或控面。若开启了代码库则同时等其构建结束。缺鉴权、IDOR、业务逻辑靠这条。',
    fast: 'Semgrep 找 Sink 后按条回推。与启发式并行，覆盖 SAST Sink。',
    bypass: '历史漏洞收集完毕后按文档逐条尝试绕过补丁或确认未修复洞仍可打。',
    unconstrained: '侦察完成后启动，只注入代码地图与鉴权。若开启了代码库则同时等其构建结束。始终走赏金闸门；Reviewer 判定前台洞达成 RCE 效果后结束。',
  }

  const codeIntel = PHASES.find((p) => p.id === 'code_intel')
  const ciOn = state.codeIntelEnabled === true
  const ciStatus = state.codeIntelStatus || 'pending'
  const ciLabel =
    !ciOn || ciStatus === 'skipped'
      ? '代码库 未开'
      : ciStatus === 'stale'
        ? '代码库 需重建'
        : ciStatus === 'degraded'
          ? '代码库 已降级'
          : '代码库'
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
                        侦察{state.reconDone ? ' ✓' : ''}
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
                      {p.id === 'reviewer' && (state.dynamicVerifyMode || (state.dynamicVerifyEnabled ? 'lab' : 'off')) === 'off' ? ' 静态' : ''}
                      {p.id === 'reviewer' && (state.dynamicVerifyMode || (state.dynamicVerifyEnabled ? 'lab' : 'off')) === 'harness' ? ' 局部' : ''}
                      {p.id === 'verifier' && !state.verifierEnabled ? ' 未开' : ''}
                      {p.id === 'attack_chain' && !state.attackChainEnabled ? ' 未开' : ''}
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
