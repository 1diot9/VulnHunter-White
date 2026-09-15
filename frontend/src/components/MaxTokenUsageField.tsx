import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'
import { cn } from '@/lib/utils'

export function maxTokenUsageHint(): string {
  return t('comp.token.hint')
}

export const MAX_TOKEN_USAGE_HINT = maxTokenUsageHint

function tokenPresets() {
  return [
    { label: t('comp.token.unlimited'), value: '' },
    { label: t('comp.token.m100'), value: '1000000' },
    { label: t('comp.token.m500'), value: '5000000' },
    { label: t('comp.token.m1000'), value: '10000000' },
  ]
}

export function parseMaxTokenUsageInput(raw: string): number {
  const text = raw.trim().replace(/,/g, '')
  if (!text) return 0
  const n = Number(text)
  if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
    throw new Error(t('comp.token.invalid'))
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
  const { t } = useI18n()
  return (
    <div className={cn('space-y-2', className)}>
      <Label htmlFor="max-token-usage" className="font-medium">
        {t('comp.token.label')}
      </Label>
      <p className="text-xs leading-relaxed text-muted-foreground">{maxTokenUsageHint()}</p>
      <Input
        id="max-token-usage"
        type="number"
        min={0}
        step={1}
        inputMode="numeric"
        value={value}
        disabled={disabled}
        placeholder={t('comp.token.placeholder')}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="flex flex-wrap gap-1.5">
        {tokenPresets().map((p) => (
          <button
            key={p.value || 'unlimited'}
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
