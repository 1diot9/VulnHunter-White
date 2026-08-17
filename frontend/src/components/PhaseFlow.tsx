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
    id: 'worker',
    label: '挖掘',
    hint: '启发式 Worker 从高权重未审计文件沿 source→sink 挖漏洞并提交。',
  },
  {
    id: 'reviewer',
    label: '审核',
    hint: '独立验证 Worker 提交的漏洞是否成立，并分层为有 CVE 价值或低危害难利用。',
  },
  {
    id: 'verifier',
    label: '验证',
    hint: '可选。Reviewer 确认前台漏洞后，用 FOFA 搜同款目标并按报告复测；默认搜 10 个，任一成功即结束。',
  },
  {
    id: 'done',
    label: '完成',
    hint: '侦察、挖掘、审核与（若开启）互联网验证均已结束。',
  },
] as const

const BRANCH_HINTS: Record<string, string> = {
  map: '梳理模块、HTTP 入口和技术栈，并写出登录 / 角色 / 权限文档。',
  source_ext: '把默认未入库的执行面文件（模板、ORM 映射等）补进索引。',
  old_vulns: '收录本项目公开洞，以及仓库里确有调用点、默认部署仍可能打到的组件漏洞。',
  mark: '按批次给源码定权或跳过，决定后续挖掘优先级。',
  lab: '用 Docker 搭建默认可复用靶场，供动态复现；不是制造利用条件。',
  manualLab: '使用用户提供的漏洞环境地址做动态验证，跳过 Docker 搭建。',
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
  filesAudited?: number
  filesSkipped?: number
  filesTotal?: number
  workerRounds?: number
  vulnPending?: number
  reconSubphases?: ReconSubphaseView[]
  labSetupDone?: boolean
  manualLab?: boolean
  verifierEnabled?: boolean
  verifierPending?: number
}

type BranchItem = {
  id: string
  node: ReactNode
}

function workerFinished(s: FlowState): boolean {
  const total = s.filesTotal ?? 0
  if (!s.reconDone || total <= 0) return false
  return (s.filesAudited ?? 0) + (s.filesSkipped ?? 0) >= total
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
  if (id === 'worker') {
    if (workerDone) return 'success'
    if (s.phase === 'worker' || s.phase === 'fix' || s.status === 'auditing' || (s.reconDone && !workerDone)) {
      return 'info'
    }
    return 'neutral'
  }
  if (id === 'reviewer') {
    if (s.labSetupDone && (s.vulnPending ?? 0) === 0 && (s.status === 'completed' || s.phase === 'done')) {
      return 'success'
    }
    if (
      !s.labSetupDone &&
      s.status !== 'pending' &&
      s.status !== 'error' &&
      s.status !== 'cancelled'
    ) {
      return 'info'
    }
    if (s.phase === 'reviewer' || s.status === 'reviewing' || (s.vulnPending ?? 0) > 0) return 'info'
    return 'neutral'
  }
  if (id === 'verifier') {
    if (!s.verifierEnabled) return 'neutral'
    if ((s.verifierPending ?? 0) === 0 && (s.status === 'completed' || s.phase === 'done')) return 'success'
    if (s.phase === 'verifier' || (s.verifierPending ?? 0) > 0) return 'info'
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

function PhaseBranch({ items }: { items: BranchItem[] }) {
  if (items.length === 0) return null
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
  filesAudited,
  filesSkipped,
  filesTotal,
  workerRounds,
  vulnPending,
  reconSubphases,
  labSetupDone,
  manualLab,
  verifierEnabled,
  verifierPending,
  onSelect,
}: FlowState & { onSelect?: (id: string) => void }) {
  const state: FlowState = {
    phase,
    status,
    reconDone,
    filesAudited,
    filesSkipped,
    filesTotal,
    workerRounds,
    vulnPending,
    reconSubphases,
    labSetupDone,
    manualLab,
    verifierEnabled,
    verifierPending,
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
    if (id === 'reviewer') {
      return [
        {
          id: 'lab',
          node: (
            <FlowTip hint={state.manualLab ? BRANCH_HINTS.manualLab : BRANCH_HINTS.lab} side="right">
              <Badge
                variant={badgeVariant(
                  state.labSetupDone ? 'success' : phaseTone('reviewer', state) === 'info' ? 'info' : 'neutral',
                )}
              >
                {state.manualLab ? '人工靶场' : '环境搭建'}
                {state.labSetupDone ? ' ✓' : ''}
              </Badge>
            </FlowTip>
          ),
        },
      ]
    }
    return []
  }

  const branches: Record<string, BranchItem[]> = {
    recon: branchOf('recon'),
    worker: branchOf('worker'),
    reviewer: branchOf('reviewer'),
    verifier: branchOf('verifier'),
    done: branchOf('done'),
  }
  const spacerCount = Math.max(...Object.values(branches).map((items) => items.length), 0)

  return (
    <TooltipProvider delay={200}>
      <div className="relative">
        <div className="flex flex-nowrap items-center gap-2">
          {PHASES.map((p, i) => (
            <Fragment key={p.id}>
              <div className="relative">
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
                      {p.id === 'worker' && workerRounds != null ? ` ${workerRounds} 轮` : ''}
                      {p.id === 'verifier' && !state.verifierEnabled ? ' 未开' : ''}
                    </Badge>
                  </FlowTip>
                </div>
                <div className="absolute left-0 top-full">
                  <PhaseBranch items={branches[p.id]} />
                </div>
              </div>
              {i < PHASES.length - 1 ? <span className="text-slate-600">→</span> : null}
            </Fragment>
          ))}
        </div>
        {spacerCount > 0 ? (
          <div className="invisible pointer-events-none" aria-hidden>
            <PhaseBranch
              items={Array.from({ length: spacerCount }, (_, i) => ({
                id: `spacer-${i}`,
                node: <span className="inline-flex h-5" />,
              }))}
            />
          </div>
        ) : null}
      </div>
    </TooltipProvider>
  )
}
