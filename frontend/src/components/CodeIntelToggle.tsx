import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

export function codeIntelHint(): string {
  return t('comp.codeIntel.hint')
}

export const CODE_INTEL_HINT = codeIntelHint

export function CodeIntelToggle({
  enabled,
  onEnabledChange,
  disabled = false,
}: {
  enabled: boolean
  onEnabledChange: (enabled: boolean) => void
  disabled?: boolean
}) {
  const { t } = useI18n()
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">{t('comp.codeIntel.title')}</p>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={enabled}
          disabled={disabled}
          onCheckedChange={(checked) => onEnabledChange(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('comp.codeIntel.build')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {codeIntelHint()}
          </span>
        </span>
      </Label>
    </div>
  )
}
