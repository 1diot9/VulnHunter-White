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

export const DYNAMIC_VERIFY_HINT = DYNAMIC_VERIFY_OPTIONS[1].hint

export function normalizeDynamicVerifyMode(
  mode: string | null | undefined,
  enabled?: boolean,
): DynamicVerifyMode {
  if (mode === 'lab' || mode === 'harness' || mode === 'off') return mode
  return enabled ? 'lab' : 'off'
}

export function formatDynamicVerifyMode(mode: string | null | undefined, enabled?: boolean): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  return DYNAMIC_VERIFY_OPTIONS.find((o) => o.value === normalized)?.label ?? '关闭'
}

export function formatDynamicVerifyHint(mode: string | null | undefined, enabled?: boolean): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  return DYNAMIC_VERIFY_OPTIONS.find((o) => o.value === normalized)?.hint ?? DYNAMIC_VERIFY_OPTIONS[0].hint
}

export function DynamicVerifyToggle({
  mode,
  enabled,
  onModeChange,
  onEnabledChange,
}: {
  mode?: string | null
  enabled?: boolean
  onModeChange?: (mode: DynamicVerifyMode) => void
  onEnabledChange?: (enabled: boolean) => void
}) {
  const value = normalizeDynamicVerifyMode(mode, enabled)
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
          <SelectValue>{formatDynamicVerifyMode(value)}</SelectValue>
        </SelectTrigger>
        <SelectContent className="w-auto min-w-80 max-w-96" alignItemWithTrigger={false} align="start">
          {DYNAMIC_VERIFY_OPTIONS.map((opt) => (
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
        {formatDynamicVerifyHint(value)}
      </p>
    </div>
  )
}
