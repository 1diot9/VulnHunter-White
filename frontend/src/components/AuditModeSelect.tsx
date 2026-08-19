import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { BountyScopeButton } from './BountyScopeDialog'
import {
  AUDIT_MODE_OPTIONS,
  cn,
  formatAuditMode,
  formatAuditModeHint,
  type AuditMode,
} from '@/lib/utils'
import type { CustomAuditMode } from '../api'

export function AuditModeSelect({
  value,
  customModeId,
  customModes = [],
  customModeName,
  onValueChange,
  onCustomModeIdChange,
  showHint = true,
  className,
}: {
  value: string | null | undefined
  customModeId?: number | null
  customModes?: CustomAuditMode[]
  customModeName?: string | null
  onValueChange: (value: AuditMode) => void
  onCustomModeIdChange?: (id: number | null) => void
  showHint?: boolean
  className?: string
}) {
  const mode: AuditMode =
    value === 'full' ? 'full' : value === 'custom' ? 'custom' : 'bounty'
  const selectedCustomId =
    customModeId != null
      ? String(customModeId)
      : customModes[0]
        ? String(customModes[0].id)
        : ''

  return (
    <div className={cn('min-w-0', className)}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Select
          value={mode}
          onValueChange={(next) => {
            if (next === 'bounty' || next === 'full' || next === 'custom') {
              onValueChange(next)
              if (next === 'custom' && onCustomModeIdChange && customModes.length && customModeId == null) {
                onCustomModeIdChange(customModes[0].id)
              }
              if (next !== 'custom' && onCustomModeIdChange) {
                onCustomModeIdChange(null)
              }
            }
          }}
        >
          <SelectTrigger className="w-auto min-w-28">
            <SelectValue>{formatAuditMode(mode, customModeName)}</SelectValue>
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
        {mode === 'custom' ? (
          <Select
            value={selectedCustomId}
            onValueChange={(next) => {
              const id = Number(next)
              if (!Number.isFinite(id)) return
              onCustomModeIdChange?.(id)
            }}
            disabled={!customModes.length}
          >
            <SelectTrigger className="w-auto min-w-36">
              <SelectValue placeholder={customModes.length ? '选择自定义模式' : '暂无自定义'} />
            </SelectTrigger>
            <SelectContent className="w-auto min-w-56 max-w-80" alignItemWithTrigger={false} align="start">
              {customModes.map((m) => (
                <SelectItem key={m.id} value={String(m.id)}>
                  {m.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : (
          <BountyScopeButton />
        )}
      </div>
      {showHint ? (
        <p className="mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground">
          {formatAuditModeHint(mode, customModeName)}
          {mode === 'custom' && !customModes.length
            ? ' 请先到设置页添加自定义审计模式。'
            : ''}
        </p>
      ) : null}
    </div>
  )
}
