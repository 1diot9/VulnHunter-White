import type { ReactNode } from 'react'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn, formatAuditMode, formatMiningPaths } from '@/lib/utils'

const RECON_STEPS = [
  { id: 'map', label: '代码地图/鉴权', hint: '梳理模块、HTTP 与非 HTTP 入口和技术栈，并写出登录 / 角色 / 权限文档。' },
  { id: 'source_ext', label: '扩展名', hint: '把默认未入库的执行面文件（模板、ORM 映射等）补进索引。' },
  { id: 'old_vulns', label: '历史漏洞', hint: '先跑 GHSA 与 GitHub Issues 爬虫，由 Agent 按爬虫结果落盘；完成后再用 WebSearch 补漏。' },
  { id: 'mark', label: '文件定权', hint: '按批次给源码定权或跳过，决定后续挖掘优先级。' },
] as const

type PreviewProps = {
  auditMode: 'bounty' | 'full' | 'custom'
  dynamicVerifyEnabled: boolean
  dynamicVerifyMode?: 'off' | 'lab' | 'harness'
  manualLab: boolean
  verifierEnabled: boolean
  attackChainEnabled?: boolean
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

function buildNodes({
  auditMode,
  dynamicVerifyEnabled,
  dynamicVerifyMode,
  manualLab,
  verifierEnabled,
  attackChainEnabled = false,
  heuristicEnabled = true,
  heuristicLite = false,
  fastEnabled = false,
  bypassEnabled = false,
  unconstrainedEnabled = false,
}: PreviewProps): FlowNode[] {
  const bounty = auditMode !== 'full'
  const verifyMode = dynamicVerifyMode || (dynamicVerifyEnabled ? 'lab' : 'off')
  const useManual = verifyMode === 'lab' && manualLab
  const labOn = verifyMode === 'lab'
  const harnessOn = verifyMode === 'harness'
  const heuristicOn = heuristicEnabled !== false
  const liteOn = heuristicOn && heuristicLite === true
  const fastOn = fastEnabled === true
  const bypassOn = bypassEnabled === true
  const unconstrainedOn = unconstrainedEnabled === true
  const scopeChip = bounty
    ? { id: 'scope', label: '只报高危害', hint: 'RCE、注入、任意文件操作、越权、存储型 XSS、1-click CSRF、有服务端机密危害的硬编码密钥等。' }
    : { id: 'scope', label: '含低危害难利用', hint: 'CORS、反射 XSS、缺速率限制、安全头等由 Reviewer 分层。' }
  const unconstrainedScopeChip = {
    id: 'scope',
    label: '只报高危害',
    hint: '本路径始终走赏金闸门，与项目全量 / 自定义模式无关。',
  }

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
  if (unconstrainedOn) {
    mines.push({
      id: 'unconstrained',
      title: '无约束扫描',
      tag: '赏金',
      body: '只注入代码地图与鉴权，不派发定权文件。固定 1 个 Worker，始终走赏金闸门。Reviewer 判定前台洞达成 RCE 效果后结束本路径；其他前台洞也要交。',
      hint: '历史漏洞收集完毕后启动，与启发式隔离。结束条件由 Reviewer 判定 RCE 效果，不看 vuln_type。',
      chips: [unconstrainedScopeChip],
    })
  }

  return [
    {
      id: 'recon',
      title: '侦察',
      body: '摸清结构与鉴权，补齐扩展名、收录历史漏洞并给文件定权。启发式、历史漏洞绕过与无约束扫描在历史漏洞收集完毕后开始；快速扫描等四步（含定权）全部完成。',
      hint: '导入后先跑侦察：代码地图、源码扩展名、历史漏洞、文件定权。启发式不等待定权全部结束。',
      chips: [...RECON_STEPS],
    },
    ...mines,
    {
      id: 'reviewer',
      title: '审核',
      tag: labOn ? '靶场动态' : harnessOn ? '局部验证' : '静态',
      body: labOn
        ? useManual
          ? '优先用你提供的靶场，不可达再回退 Docker。Reviewer 改 PoC 并复现；不要打回 Worker 改 PoC。'
          : '独立环境轮搭建 Docker 靶场。Reviewer 改 PoC 并复现；不要打回 Worker 改 PoC。'
        : harnessOn
          ? '不搭整项目靶场。Reviewer 抽出函数、mock 依赖，在沙箱跑 harness；打通记为局部验证。'
          : '只做静态复核。能证明默认可利用则以 static_only 入库，不搭靶场。',
      hint: labOn
        ? '靶场动态开启后，Reviewer 才搭靶场并收口 HTTP PoC；PoC 不可用需改写时才用 debug MCP。靶场只提供默认部署。'
        : harnessOn
          ? '局部验证与靶场动态互斥。无 Docker 或 mock 失败不因此误报。'
          : '默认关闭动态验证。静态已能证明默认可利用时直接入库，不跑 Docker。',
      chips: labOn
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
              hint: '先跑当前 HTTP PoC 与容器日志。PoC 由 Reviewer 改到可复现；缺失、跑不通或复现失败且需改写时，才用 Java / Node / Python debug MCP。不要打回 Worker 改 PoC。',
            },
          ]
        : harnessOn
          ? [
              {
                id: 'harness',
                label: '沙箱 harness',
                hint: 'RunCode 在一次性 sibling 容器执行；脚本写入 harness.py。不要把 mock 抄进 poc.py；纯库洞无安装面可不交 poc.py。',
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
        : '未开启。确认后不搜互联网目标。',
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
      id: 'attack_chain',
      title: '攻击链',
      tag: attackChainEnabled ? '串联' : '未开',
      skipped: !attackChainEnabled,
      body: attackChainEnabled
        ? '挖掘与审核结束后，根据已确认漏洞尝试多步串联利用，扩大危害。'
        : '未开启。审核结束后不进入攻击链串联。',
      hint: attackChainEnabled
        ? '只看本项目已确认产出；已确认洞少于 2 条时自动跳过。有 Docker 靶场时对无交互链动态验证并落盘脚本；XSS 等需交互的链跳过验证。'
        : '攻击链串联默认关闭。勾选后才会在挖掘与审核都结束后尝试多漏洞串联。',
      chips: attackChainEnabled
        ? [
            { id: 'confirmed', label: '仅已确认', hint: 'pending / 误报 / 已合并子条不参与。' },
            { id: 'min2', label: '至少 2 条', hint: '少于 2 条已确认洞时跳过，不空跑 LLM。' },
          ]
        : [],
    },
    {
      id: 'done',
      title: '完成',
      body:
        verifierEnabled || attackChainEnabled
          ? '侦察、挖掘、审核与已开启的后置阶段均结束，产出漏洞报告。'
          : '侦察、挖掘与审核结束，产出漏洞报告。',
      hint: '流水线结束。之后仍可在项目配置里改动态验证、互联网验证或攻击链串联，或重置挖掘进度后换模式续跑。',
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

function summaryText({
  auditMode,
  dynamicVerifyEnabled,
  dynamicVerifyMode,
  manualLab,
  verifierEnabled,
  attackChainEnabled = false,
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
      ? manualLab
        ? '靶场动态（人工靶场优先）'
        : '靶场动态'
      : verifyMode === 'harness'
        ? '局部验证'
        : '静态复核'
  const post: string[] = []
  if (verifierEnabled) post.push('互联网验证')
  if (attackChainEnabled) post.push('攻击链')
  const tail = post.length > 0 ? `${post.join(' ∥ ')} → 完成` : '完成'
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
                <FlowConnector down="提交漏洞" back="分析债务 / Fix" />
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
          历史漏洞收集完毕后启发式、历史漏洞绕过与无约束扫描可与定权并行；快速扫描等侦察四步完成。开启的挖掘路径并行推进，并与审核并行：一边挖一边审。明显误报本轮丢弃；PoC 与报告包装由 Reviewer 改完确认；仅根因分析错了才打回 Fix 再审。开启的挖掘路径都结束后项目才完成。
        </p>
      </section>
    </TooltipProvider>
  )
}
