import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

export function manualLabHint(): string {
  return t('comp.manual.hint')
}

export function manualLabPlaceholder(): string {
  return t('comp.manual.placeholder')
}

/** @deprecated call manualLabHint() */
export const MANUAL_LAB_HINT = manualLabHint
/** @deprecated call manualLabPlaceholder() */
export const MANUAL_LAB_PLACEHOLDER = manualLabPlaceholder

export function ManualLabToggle({
  enabled,
  prompt,
  onEnabledChange,
  onPromptChange,
}: {
  enabled: boolean
  prompt: string
  onEnabledChange: (enabled: boolean) => void
  onPromptChange: (prompt: string) => void
}) {
  const { t } = useI18n()
  return (
    <div className="space-y-2">
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={enabled}
          onCheckedChange={(checked) => onEnabledChange(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('comp.manual.title')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {manualLabHint()}
          </span>
        </span>
      </Label>
      {enabled ? (
        <Textarea
          value={prompt}
          onChange={(e) => onPromptChange(e.target.value)}
          placeholder={manualLabPlaceholder()}
          rows={4}
        />
      ) : null}
    </div>
  )
}
