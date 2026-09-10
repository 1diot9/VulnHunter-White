import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'

export type DynamicVerifyMode = 'off' | 'lab' | 'harness'

export const DYNAMIC_VERIFY_OPTIONS = [
  {
    value: 'off' as const,
    label: '关闭',
    short: '仅静态复核',
    hint: 'Reviewer 只做静态审核，Confirm 用 static_only。默认选项。',
  },
  {
    value: 'lab' as const,
    label: '靶场动态',
    short: 'Docker / 人工靶场 + HTTP PoC',
    hint: '独立环境轮搭建 Docker 靶场（或填写人工靶场），用 HTTP PoC / debug MCP 复现。证据等级 dynamic / mcp。',
  },
  {
    value: 'harness' as const,
    label: '局部验证',
    short: '沙箱 mock / harness',
    hint: '不搭整项目靶场。Reviewer 抽出函数、mock 依赖，在 Docker 沙箱跑 harness。打通记为局部验证，与靶场动态区分。无 Docker 则退静态。',
  },
] as const

/** Docker Desktop edition: lab means manual target only (no auto build). */
export const DOCKER_LAB_OPTION = {
  value: 'lab' as const,
  label: '人工靶场',
  short: '用户提供已有 URL + HTTP PoC',
  hint:
    '不自动搭建被测应用镜像。填写本机或局域网靶场地址/账号；127.0.0.1 会改写为 host.docker.internal 以便容器内访问。不可达时仅静态或误报。',
} as const

export const DYNAMIC_VERIFY_HINT = DYNAMIC_VERIFY_OPTIONS[1].hint

export function verifyOptionsForRuntime(dockerLabBuildEnabled: boolean) {
  if (dockerLabBuildEnabled) return [...DYNAMIC_VERIFY_OPTIONS]
  return [
    DYNAMIC_VERIFY_OPTIONS[0],
    DYNAMIC_VERIFY_OPTIONS[2],
    DOCKER_LAB_OPTION,
  ]
}

export function normalizeDynamicVerifyMode(
  mode: string | null | undefined,
  enabled?: boolean,
): DynamicVerifyMode {
  if (mode === 'lab' || mode === 'harness' || mode === 'off') return mode
  return enabled ? 'lab' : 'off'
}

export function formatDynamicVerifyMode(
  mode: string | null | undefined,
  enabled?: boolean,
  dockerLabBuildEnabled = true,
): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  if (!dockerLabBuildEnabled && normalized === 'lab') return DOCKER_LAB_OPTION.label
  return DYNAMIC_VERIFY_OPTIONS.find((o) => o.value === normalized)?.label ?? '关闭'
}

export function formatDynamicVerifyHint(
  mode: string | null | undefined,
  enabled?: boolean,
  dockerLabBuildEnabled = true,
): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  if (!dockerLabBuildEnabled && normalized === 'lab') return DOCKER_LAB_OPTION.hint
  return DYNAMIC_VERIFY_OPTIONS.find((o) => o.value === normalized)?.hint ?? DYNAMIC_VERIFY_OPTIONS[0].hint
}

export function DynamicVerifyToggle({
  mode,
  enabled,
  onModeChange,
  onEnabledChange,
  dockerLabBuildEnabled = true,
}: {
  mode?: string | null
  enabled?: boolean
  onModeChange?: (mode: DynamicVerifyMode) => void
  onEnabledChange?: (enabled: boolean) => void
  /** False in Docker Desktop edition — hide auto Docker lab, show 人工靶场. */
  dockerLabBuildEnabled?: boolean
}) {
  const value = normalizeDynamicVerifyMode(mode, enabled)
  const options = verifyOptionsForRuntime(dockerLabBuildEnabled)
  return (
    <div className="min-w-0">
      <div className="text-sm font-medium">验证方式</div>
      <Select
        value={value}
        onValueChange={(next) => {
          if (next !== 'off' && next !== 'lab' && next !== 'harness') return
          onModeChange?.(next)
          onEnabledChange?.(next !== 'off')
        }}
      >
        <SelectTrigger className="mt-1.5 w-auto min-w-36">
          <SelectValue>{formatDynamicVerifyMode(value, enabled, dockerLabBuildEnabled)}</SelectValue>
        </SelectTrigger>
        <SelectContent className="w-auto min-w-80 max-w-96" alignItemWithTrigger={false} align="start">
          {options.map((opt) => (
            <SelectItem key={opt.value} value={opt.value} className="items-start py-2">
              <span className="flex max-w-80 flex-col gap-0.5 whitespace-normal">
                <span>{opt.label}</span>
                <span className="text-xs font-normal whitespace-normal text-muted-foreground">{opt.short}</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className={cn('mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground')}>
        {formatDynamicVerifyHint(value, enabled, dockerLabBuildEnabled)}
      </p>
    </div>
  )
}
