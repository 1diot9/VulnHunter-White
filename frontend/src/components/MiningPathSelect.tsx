import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useI18n } from '@/i18n'

type MiningPathValue = {
  heuristicEnabled: boolean
  heuristicLite: boolean
  fastEnabled: boolean
  bypassEnabled: boolean
  unconstrainedEnabled: boolean
}

type Props = {
  heuristicEnabled: boolean
  heuristicLite?: boolean
  fastEnabled: boolean
  bypassEnabled?: boolean
  unconstrainedEnabled?: boolean
  onChange: (next: MiningPathValue) => void
  disabled?: boolean
}

export function MiningPathSelect({
  heuristicEnabled,
  heuristicLite = false,
  fastEnabled,
  bypassEnabled = false,
  unconstrainedEnabled = false,
  onChange,
  disabled = false,
}: Props) {
  const { t } = useI18n()
  const emit = (next: Partial<MiningPathValue>) =>
    onChange({
      heuristicEnabled,
      heuristicLite,
      fastEnabled,
      bypassEnabled,
      unconstrainedEnabled,
      ...next,
    })

  const othersOn = (except: 'heuristic' | 'fast' | 'bypass' | 'unconstrained') => {
    if (except !== 'heuristic' && heuristicEnabled) return true
    if (except !== 'fast' && fastEnabled) return true
    if (except !== 'bypass' && bypassEnabled) return true
    if (except !== 'unconstrained' && unconstrainedEnabled) return true
    return false
  }

  const setHeuristic = (next: boolean) => {
    if (!next && !othersOn('heuristic')) return
    emit({ heuristicEnabled: next, heuristicLite: next ? heuristicLite : false })
  }
  const setLite = (next: boolean) => {
    if (!heuristicEnabled) return
    emit({ heuristicLite: next })
  }
  const setFast = (next: boolean) => {
    if (!next && !othersOn('fast')) return
    emit({ fastEnabled: next })
  }
  const setBypass = (next: boolean) => {
    if (!next && !othersOn('bypass')) return
    emit({ bypassEnabled: next })
  }
  const setUnconstrained = (next: boolean) => {
    if (!next && !othersOn('unconstrained')) return
    emit({ unconstrainedEnabled: next })
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">{t('comp.mine.title')}</p>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={heuristicEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setHeuristic(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('comp.mine.heuristic')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {t('comp.mine.heuristicHint')}
          </span>
        </span>
      </Label>
      <Label className="items-start pl-6 font-normal">
        <Checkbox
          className="mt-0.5"
          checked={heuristicEnabled && heuristicLite}
          disabled={disabled || !heuristicEnabled}
          onCheckedChange={(checked) => setLite(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('comp.mine.lite')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {t('comp.mine.liteHint')}
          </span>
        </span>
      </Label>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={fastEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setFast(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('mining.fast')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {t('comp.mine.fastHint')}
          </span>
        </span>
      </Label>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={bypassEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setBypass(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('mining.bypass')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {t('comp.mine.bypassHint')}
          </span>
        </span>
      </Label>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={unconstrainedEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setUnconstrained(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">{t('mining.unconstrained')}</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {t('comp.mine.unconstHint')}
          </span>
        </span>
      </Label>
    </div>
  )
}
