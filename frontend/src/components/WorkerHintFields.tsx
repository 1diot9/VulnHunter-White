import { HINT_TEXT_MAX, HintTextFields } from './HintTextFields'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

export const WORKER_HINT_MAX = HINT_TEXT_MAX

export function workerHintHint(): string {
  return t('comp.workerHint.hint')
}

export function workerHintPlaceholder(): string {
  return t('comp.workerHint.placeholder')
}

export const WORKER_HINT_HINT = workerHintHint
export const WORKER_HINT_PLACEHOLDER = workerHintPlaceholder

export function WorkerHintFields({
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
      id="worker-hint"
      label={t('comp.workerHint.label')}
      hint={workerHintHint()}
      placeholder={workerHintPlaceholder()}
      value={value}
      onChange={onChange}
      disabled={disabled}
      tooLongMessage={t('comp.workerHint.tooLong', { max: WORKER_HINT_MAX })}
    />
  )
}
