import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import {
  AUDIT_MODE_OPTIONS,
  cn,
  formatAuditMode,
  formatAuditModeHint,
  type AuditMode,
} from '@/lib/utils'

export function AuditModeSelect({
  value,
  onValueChange,
  showHint = true,
  className,
}: {
  value: string | null | undefined
  onValueChange: (value: AuditMode) => void
  showHint?: boolean
  className?: string
}) {
  const mode: AuditMode = value === 'full' ? 'full' : 'bounty'
  return (
    <div className={cn('min-w-0', className)}>
      <Select
        value={mode}
        onValueChange={(next) => {
          if (next === 'bounty' || next === 'full') onValueChange(next)
        }}
      >
        <SelectTrigger className="w-auto min-w-28">
          <SelectValue>{formatAuditMode(mode)}</SelectValue>
        </SelectTrigger>
        <SelectContent className="w-auto min-w-72 max-w-80" alignItemWithTrigger={false} align="start">
          {AUDIT_MODE_OPTIONS.map((opt) => (
            <SelectItem key={opt.value} value={opt.value} className="items-start py-2">
              <span className="flex max-w-72 flex-col gap-0.5 whitespace-normal">
                <span>{opt.label}</span>
                <span className="text-xs font-normal whitespace-normal text-muted-foreground">{opt.short}</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {showHint ? (
        <p className="mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground">{formatAuditModeHint(mode)}</p>
      ) : null}
    </div>
  )
}
