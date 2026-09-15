import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

export function attackChainHint(): string {
  return t('comp.attackChain.hint')
}

export const ATTACK_CHAIN_HINT = attackChainHint

export function AttackChainToggle({
  enabled,
  onEnabledChange,
}: {
  enabled: boolean
  onEnabledChange: (enabled: boolean) => void
}) {
  const { t } = useI18n()
  return (
    <Label className="items-start font-normal">
      <Checkbox
        className="mt-0.5"
        checked={enabled}
        onCheckedChange={(checked) => onEnabledChange(checked === true)}
      />
      <span className="min-w-0">
        <span className="font-medium">{t('comp.attackChain.title')}</span>
        <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
          {attackChainHint()}
        </span>
      </span>
    </Label>
  )
}
