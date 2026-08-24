import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  TARGET_KIND_OPTIONS,
  cn,
  formatTargetKind,
  formatTargetKindHint,
  normalizeTargetKind,
  type TargetKind,
} from '@/lib/utils'

export function TargetKindSelect({
  value,
  onValueChange,
  showHint = true,
  disabled = false,
  className,
}: {
  value: string | null | undefined
  onValueChange: (value: TargetKind) => void
  showHint?: boolean
  disabled?: boolean
  className?: string
}) {
  const kind = normalizeTargetKind(value)

  return (
    <div className={cn('min-w-0', className)}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-sm text-muted-foreground">审计对象</span>
        <Select
          value={kind}
          disabled={disabled}
          onValueChange={(next) => {
            if (next === 'web' || next === 'library' || next === 'mixed') {
              onValueChange(next)
            }
          }}
        >
          <SelectTrigger className="w-auto min-w-28">
            <SelectValue>{formatTargetKind(kind)}</SelectValue>
          </SelectTrigger>
          <SelectContent className="w-auto min-w-72 max-w-80" alignItemWithTrigger={false} align="start">
            {TARGET_KIND_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="items-start py-2">
                <span className="flex max-w-72 flex-col gap-0.5 whitespace-normal">
                  <span>{opt.label}</span>
                  <span className="text-xs font-normal whitespace-normal text-muted-foreground">{opt.short}</span>
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {showHint ? (
        <p className="mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground">
          {formatTargetKindHint(kind)}
        </p>
      ) : null}
    </div>
  )
}
