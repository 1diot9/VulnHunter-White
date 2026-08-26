import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

export const MAX_TOKEN_USAGE_HINT =
  '按本项目全部 Agent 的输入 + 输出 Token 合计。到达后自动暂停全部阶段；在项目配置中提高上限（或改为不限制）后再续跑。留空或 0 表示不限制。'

const PRESETS: { label: string; value: string }[] = [
  { label: '不限制', value: '' },
  { label: '100 万', value: '1000000' },
  { label: '500 万', value: '5000000' },
  { label: '1000 万', value: '10000000' },
]

export function parseMaxTokenUsageInput(raw: string): number {
  const text = raw.trim().replace(/,/g, '')
  if (!text) return 0
  const n = Number(text)
  if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
    throw new Error('Token 上限必须是非负整数，0 表示不限制')
  }
  return n
}

export function formatMaxTokenUsageInput(value: number | null | undefined): string {
  const n = Number(value || 0)
  return n > 0 ? String(n) : ''
}

export function MaxTokenUsageField({
  value,
  onChange,
  disabled = false,
  className,
}: {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  className?: string
}) {
  return (
    <div className={cn('space-y-2', className)}>
      <Label htmlFor="max-token-usage" className="font-medium">
        最大 Token 使用量
      </Label>
      <p className="text-xs leading-relaxed text-muted-foreground">{MAX_TOKEN_USAGE_HINT}</p>
      <Input
        id="max-token-usage"
        type="number"
        min={0}
        step={1}
        inputMode="numeric"
        value={value}
        disabled={disabled}
        placeholder="0 或不填表示不限制"
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="flex flex-wrap gap-1.5">
        {PRESETS.map((p) => (
          <button
            key={p.label}
            type="button"
            disabled={disabled}
            className="rounded-md border border-input px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-muted disabled:pointer-events-none disabled:opacity-50"
            onClick={() => onChange(p.value)}
          >
            {p.label}
          </button>
        ))}
      </div>
    </div>
  )
}
