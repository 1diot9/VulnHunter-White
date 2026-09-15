import { HINT_TEXT_MAX, HintTextFields } from './HintTextFields'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

export const RECON_HINT_MAX = HINT_TEXT_MAX

export function reconHintHint(): string {
  return t('comp.reconHint.hint')
}

export function reconHintPlaceholder(): string {
  return t('comp.reconHint.placeholder')
}

export const RECON_HINT_HINT = reconHintHint
export const RECON_HINT_PLACEHOLDER = reconHintPlaceholder

export function ReconHintFields({
  value,
  onChange,
  disabled = false,
}: {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}) {
  const { t } = useI18n()
  return (
    <HintTextFields
      id="recon-hint"
      label={t('comp.reconHint.label')}
      hint={reconHintHint()}
      placeholder={reconHintPlaceholder()}
      value={value}
      onChange={onChange}
      disabled={disabled}
      tooLongMessage={t('comp.reconHint.tooLong', { max: RECON_HINT_MAX })}
    />
  )
}
