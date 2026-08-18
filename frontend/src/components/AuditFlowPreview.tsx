import type { ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn, formatAuditMode, formatMiningPaths } from '@/lib/utils'

const RECON_STEPS = [
  { id: 'map', label: '代码地图/鉴权', hint: '梳理模块、HTTP 与非 HTTP 入口和技术栈，并写出登录 / 角色 / 权限文档。' },
  { id: 'source_ext', label: '扩展名', hint: '把默认未入库的执行面文件（模板、ORM 映射等）补进索引。' },
  { id: 'old_vulns', label: '历史漏洞', hint: '先检索本项目公开洞与仍可能打到的组件调用点，再跑 GHSA 与 GitHub Issues 爬虫补漏并核验。' },
  { id: 'mark', label: '文件定权', hint: '按批次给源码定权或跳过，决定后续挖掘优先级。' },
] as const

type PreviewProps = {
  auditMode: 'bounty' | 'full'
  dynamicVerifyEnabled: boolean
  manualLab: boolean
  verifierEnabled: boolean
  heuristicEnabled?: boolean
  heuristicLite?: boolean
  fastEnabled?: boolean
  bypassEnabled?: boolean
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

function buildNodes({
  auditMode,
  dynamicVerifyEnabled,
  manualLab,
  verifierEnabled,
  heuristicEnabled = true,
  heuristicLite = false,
  fastEnabled = false,
  bypassEnabled = false,
}: PreviewProps): FlowNode[] {
  const bounty = auditMode !== 'full'
  const useManual = dynamicVerifyEnabled && manualLab
  const heuristicOn = heuristicEnabled !== false
  const liteOn = heuristicOn && heuristicLite === true
  const fastOn = fastEnabled === true
  const bypassOn = bypassEnabled === true
  const scopeChip = bounty
    ? { id: 'scope', label: '只报高危害', hint: 'RCE、注入、任意文件操作、越权、存储型 XSS、源码硬编码密钥等。' }
    : { id: 'scope', label: '含低危害难利用', hint: 'CORS、反射 XSS、缺速率限制、安全头等由 Reviewer 分层。' }

  const mines: FlowNode[] = []
  if (heuristicOn) {
    mines.push({
      id: 'heuristic',
      title: liteOn ? '启发式轻量' : '启发式',
      tag: bounty ? '赏金' : '全量',
      body: liteOn
        ? bounty
          ? '只把权重 100 的入口当焦点（含 HTTP / WebSocket / RPC / MQ），正向 source→sink。缺鉴权、IDOR、业务逻辑靠这条。只报默认可利用的高危害。'
          : '只把权重 100 的入口当焦点（含 HTTP / WebSocket / RPC / MQ），正向 source→sink。缺鉴权、IDOR、业务逻辑靠这条。同时收录 CORS、反射 XSS 等低危害难利用项。'
        : bounty
          ? '按文件定权：入口正向挖，Service / 过滤器回推或控面，低权薄扫。缺鉴权、IDOR、业务逻辑靠这条。只报默认可利用的高危害。'
          : '按文件定权：入口正向挖，Service / 过滤器回推或控面，低权薄扫。缺鉴权、IDOR、业务逻辑靠这条。同时收录 CORS、反射 XSS 等低危害难利用项。',
      hint: liteOn
        ? '历史漏洞收集完毕后，启发式 Worker 只注入权重 100 的未审计文件；更低权重不作为入口、不阻塞完成。可与文件定权并行。'
        : '历史漏洞收集完毕后，启发式 Worker 从高权未审计文件挖洞；可与文件定权并行。开启的挖掘路径并行，都结束后才算挖掘完成。',
      chips: [scopeChip],
    })
  }
  if (fastOn) {
    mines.push({
      id: 'fast',
      title: '快速扫描',
      tag: bounty ? '赏金' : '全量',
      body: bounty
        ? 'Semgrep 找 Sink，代码筛 + Agent 筛选后按条回推。覆盖 SAST Sink；缺鉴权 / IDOR / 业务逻辑不在范围内。只报高危害。'
        : 'Semgrep 找 Sink，代码筛 + Agent 筛选后按条回推。覆盖 SAST Sink；缺鉴权 / IDOR / 业务逻辑不在范围内。同时收录低危害难利用项。',
      hint: 'Recon 后 Semgrep → 代码筛 → Sink 筛选 → Fast Worker 按条回推；与启发式并行。',
      chips: [scopeChip],
    })
  }
  if (bypassOn) {
    mines.push({
      id: 'bypass',
      title: '历史漏洞绕过',
      tag: bounty ? '赏金' : '全量',
      body: bounty
        ? '以历史漏洞文档为输入，每轮尝试绕过一条补丁或确认未修复洞仍可打。只报默认可利用的高危害。'
        : '以历史漏洞文档为输入，每轮尝试绕过一条补丁或确认未修复洞仍可打。同时收录低危害难利用项。',
      hint: '历史漏洞收集完毕后按文档逐条注入；与启发式 / 快速扫描并行。',
      chips: [scopeChip],
    })
  }

  return [
    {
      id: 'recon',
      title: '侦察',
      body: '摸清结构与鉴权，补齐扩展名、收录历史漏洞并给文件定权。启发式和历史漏洞绕过在历史漏洞收集完毕后开始；快速扫描等四步（含定权）全部完成。',
      hint: '导入后先跑侦察：代码地图、源码扩展名、历史漏洞、文件定权。启发式不等待定权全部结束。',
      chips: [...RECON_STEPS],
    },
    ...mines,
    {
      id: 'reviewer',
      title: '审核',
      tag: dynamicVerifyEnabled ? '动态' : '静态',
      body: dynamicVerifyEnabled
        ? useManual
          ? '优先用你提供的靶场，不可达再回退 Docker。用 HTTP PoC 或 debug MCP 复现后再确认。'
          : '独立环境轮搭建 Docker 靶场，用 HTTP PoC 或 debug MCP 复现后再确认。'
        : '只做静态复核。能证明默认可利用则以 static_only 入库，不搭靶场。',
      hint: dynamicVerifyEnabled
        ? '动态验证开启后，Reviewer 才搭靶场并做 HTTP / MCP 复现；靶场只提供默认部署。'
        : '默认关闭动态验证。静态已能证明默认可利用时直接入库，不跑 Docker。',
      chips: dynamicVerifyEnabled
        ? [
            {
              id: 'lab',
              label: useManual ? '人工靶场优先' : '环境搭建',
              hint: useManual
                ? '审核时优先用人工靶场地址；不可达再回退 Docker 靶场。'
                : '用 Docker 搭建默认可复用靶场，供动态复现；不是制造利用条件。',
            },
            {
              id: 'poc',
              label: 'HTTP / MCP',
              hint: '有 Java / Node / Python debug MCP 则优先动态复现，否则走 HTTP PoC 与容器日志。',
            },
          ]
        : [{ id: 'static', label: 'static_only', hint: '不搭靶场；静态证据充分即可确认入库。' }],
    },
    {
      id: 'verifier',
      title: '验证',
      tag: verifierEnabled ? 'FOFA' : '未开',
      skipped: !verifierEnabled,
      body: verifierEnabled
        ? 'Reviewer 确认前台漏洞后，用 FOFA 搜同款目标并按报告复测；默认 10 个，成功 3 个即结束。'
        : '未开启。确认后不搜互联网目标，审核结束即进入完成。',
      hint: verifierEnabled
        ? '当前这批 10 个凑不满 3 个成功时，保留已成功的并再搜下一轮，最多 5 轮（合计最多 50 个目标）。语法有命中后项目内共享。任意文件删除、DoS、SQL 增删改等破坏性漏洞会跳过。需配置 FOFA Key。'
        : '互联网验证默认关闭。勾选后才会在确认前台漏洞后做 FOFA 复测。',
      chips: verifierEnabled
        ? [
            { id: 'frontend', label: '仅前台洞', hint: '后台漏洞不走互联网复测。' },
            { id: 'three', label: '成功 3 个', hint: '每轮 10 个凑满 3 个成功即结束；不足则保留已成功的并再搜下一轮，最多 5 轮 / 50 个目标。' },
            { id: 'skip', label: '破坏性跳过', hint: '任意文件删除、DoS、SQL 增删改等会中断业务的漏洞自动跳过。' },
          ]
        : [],
    },
    {
      id: 'done',
      title: '完成',
      body: verifierEnabled
        ? '侦察、挖掘、审核与互联网验证均结束，产出漏洞报告。'
        : '侦察、挖掘与审核结束，产出漏洞报告。',
      hint: '流水线结束。之后仍可在项目配置里改动态验证或互联网验证，或重置挖掘进度后换模式续跑。',
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
        'w-full rounded-lg border px-3 py-2.5 transition-colors',
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
          nodes.length >= 3 ? 'grid-cols-3' : 'grid-cols-2',
        )}
      >
        <div
          className={cn(
            'pointer-events-none absolute top-0 h-px bg-slate-600',
            nodes.length >= 3 ? 'left-[16.67%] right-[16.67%]' : 'left-1/4 right-1/4',
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
            nodes.length >= 3 ? 'left-[16.67%] right-[16.67%]' : 'left-1/4 right-1/4',
          )}
          aria-hidden
        />
      </div>
    </div>
  )
}

function isMineNode(id: string) {
  return id === 'heuristic' || id === 'fast' || id === 'bypass'
}

function summaryText({
  auditMode,
  dynamicVerifyEnabled,
  manualLab,
  verifierEnabled,
  heuristicEnabled = true,
  heuristicLite = false,
  fastEnabled = false,
  bypassEnabled = false,
}: PreviewProps): string {
  const mode = formatAuditMode(auditMode)
  const paths = formatMiningPaths({
    heuristic_enabled: heuristicEnabled,
    heuristic_lite: heuristicLite,
    fast_enabled: fastEnabled,
    bypass_enabled: bypassEnabled,
  })
  const onCount =
    (heuristicEnabled !== false ? 1 : 0) + (fastEnabled === true ? 1 : 0) + (bypassEnabled === true ? 1 : 0)
  const mine = onCount > 1 ? `${mode} · ${paths.replaceAll(' + ', ' ∥ ')}` : `${mode} · ${paths}`
  const review = dynamicVerifyEnabled
    ? manualLab
      ? '动态验证（人工靶场优先）'
      : '动态验证'
    : '静态复核'
  const tail = verifierEnabled ? '互联网验证 → 完成' : '完成'
  return `侦察 →（${mine}）→ 审核（${review}）→ ${tail}`
}

export function AuditFlowPreview(props: PreviewProps) {
  const nodes = buildNodes(props)
  const summary = summaryText(props)
  const recon = nodes.find((n) => n.id === 'recon')
  const mines = nodes.filter((n) => isMineNode(n.id))
  const rest = nodes.filter((n) => n.id !== 'recon' && !isMineNode(n.id))

  return (
    <TooltipProvider delay={200}>
      <section
        className={cn('rounded-xl bg-muted/25 p-3 ring-1 ring-foreground/10', props.className)}
        aria-label="当前勾选下的审计流程"
      >
        <h2 className="text-xs font-medium text-muted-foreground">当前勾选下的审计流程</h2>
        <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{summary}</p>
        <div className="mt-3">
          {recon ? <FlowBox node={recon} /> : null}
          <FlowFork nodes={mines} />
          {rest.map((node) => (
            <div key={node.id}>
              {node.id === 'reviewer' ? (
                <FlowConnector down="提交漏洞" back="打回 / Fix" />
              ) : node.id === 'verifier' && node.skipped ? (
                <FlowConnector down="跳过" />
              ) : (
                <FlowConnector />
              )}
              <FlowBox node={node} />
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
          历史漏洞收集完毕后启发式与历史漏洞绕过可与定权并行；快速扫描等侦察四步完成。开启的挖掘路径并行推进，并与审核并行：一边挖一边审。证据不足或需改报告时，打回 Worker / Fix 再审。开启的挖掘路径都结束后项目才完成。
        </p>
      </section>
    </TooltipProvider>
  )
}
