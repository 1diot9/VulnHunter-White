import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'

export type DynamicVerifyMode = 'off' | 'lab' | 'harness'

export function getDynamicVerifyOptions() {
  return [
    {
      value: 'off' as const,
      label: t('verify.off'),
      short: t('verify.offShort'),
      hint: t('verify.offHint'),
    },
    {
      value: 'lab' as const,
      label: t('verify.lab'),
      short: t('verify.labShort'),
      hint: t('verify.labHint'),
    },
    {
      value: 'harness' as const,
      label: t('verify.harness'),
      short: t('verify.harnessShort'),
      hint: t('verify.harnessHint'),
    },
  ]
}

/** Docker Desktop edition: lab means manual target only (no auto build). */
export function getDockerLabOption() {
  return {
    value: 'lab' as const,
    label: t('verify.manual'),
    short: t('verify.manualShort'),
    hint: t('verify.manualHint'),
  }
}

/** @deprecated use getDynamicVerifyOptions() so labels follow UI locale */
export const DYNAMIC_VERIFY_OPTIONS = getDynamicVerifyOptions()

/** @deprecated use getDockerLabOption() */
export const DOCKER_LAB_OPTION = getDockerLabOption()

export const DYNAMIC_VERIFY_HINT = () => getDynamicVerifyOptions()[1].hint

export function verifyOptionsForRuntime(dockerLabBuildEnabled: boolean) {
  const opts = getDynamicVerifyOptions()
  if (dockerLabBuildEnabled) return [...opts]
  return [opts[0], opts[2], getDockerLabOption()]
}

export function normalizeDynamicVerifyMode(
  mode: string | null | undefined,
  enabled?: boolean,
): DynamicVerifyMode {
  if (mode === 'lab' || mode === 'harness' || mode === 'off') return mode
  return enabled ? 'lab' : 'off'
}

export function formatDynamicVerifyMode(
  mode: string | null | undefined,
  enabled?: boolean,
  dockerLabBuildEnabled = true,
): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  if (!dockerLabBuildEnabled && normalized === 'lab') return getDockerLabOption().label
  return getDynamicVerifyOptions().find((o) => o.value === normalized)?.label ?? t('verify.off')
}

export function formatDynamicVerifyHint(
  mode: string | null | undefined,
  enabled?: boolean,
  dockerLabBuildEnabled = true,
): string {
  const normalized = normalizeDynamicVerifyMode(mode, enabled)
  const opts = getDynamicVerifyOptions()
  if (!dockerLabBuildEnabled && normalized === 'lab') return getDockerLabOption().hint
  return opts.find((o) => o.value === normalized)?.hint ?? opts[0].hint
}

export function DynamicVerifyToggle({
  mode,
  enabled,
  onModeChange,
  onEnabledChange,
  dockerLabBuildEnabled = true,
}: {
  mode?: string | null
  enabled?: boolean
  onModeChange?: (mode: DynamicVerifyMode) => void
  onEnabledChange?: (enabled: boolean) => void
  /** False in Docker Desktop edition — hide auto Docker lab, show 人工靶场. */
  dockerLabBuildEnabled?: boolean
}) {
  const { t } = useI18n()
  const value = normalizeDynamicVerifyMode(mode, enabled)
  const options = verifyOptionsForRuntime(dockerLabBuildEnabled)
  return (
    <div className="min-w-0">
      <div className="text-sm font-medium">{t('verify.title')}</div>
      <Select
        value={value}
        onValueChange={(next) => {
          if (next !== 'off' && next !== 'lab' && next !== 'harness') return
          onModeChange?.(next)
          onEnabledChange?.(next !== 'off')
        }}
      >
        <SelectTrigger className="mt-1.5 w-auto min-w-36">
          <SelectValue>{formatDynamicVerifyMode(value, enabled, dockerLabBuildEnabled)}</SelectValue>
        </SelectTrigger>
        <SelectContent className="w-auto min-w-80 max-w-96" alignItemWithTrigger={false} align="start">
          {options.map((opt) => (
            <SelectItem key={opt.value} value={opt.value} className="items-start py-2">
              <span className="flex max-w-80 flex-col gap-0.5 whitespace-normal">
                <span>{opt.label}</span>
                <span className="text-xs font-normal whitespace-normal text-muted-foreground">{opt.short}</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className={cn('mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground')}>
        {formatDynamicVerifyHint(value, enabled, dockerLabBuildEnabled)}
      </p>
    </div>
  )
}
