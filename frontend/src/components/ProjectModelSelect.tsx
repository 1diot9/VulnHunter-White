import { useEffect, useMemo, useState } from 'react'
import { api, formatApiError } from '../api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'
import { cn } from '@/lib/utils'

const GLOBAL = '__global__'
const NONE = '__none__'

export function projectModelHint(): string {
  return t('comp.model.hint')
}

export const PROJECT_MODEL_HINT = projectModelHint

export function ProjectModelSelect({
  value,
  onValueChange,
  className,
}: {
  value: string
  onValueChange: (value: string) => void
  className?: string
}) {
  const { t } = useI18n()
  const [defaultModel, setDefaultModel] = useState('')
  const [models, setModels] = useState<string[]>([])
  const [modelFilter, setModelFilter] = useState('')
  const [listing, setListing] = useState(false)
  const [listError, setListError] = useState('')

  useEffect(() => {
    api
      .getSettings()
      .then((s) => setDefaultModel(s.default_model || ''))
      .catch(() => {})
  }, [])

  const filteredModels = useMemo(() => {
    const q = modelFilter.trim().toLowerCase()
    if (!q) return models
    return models.filter((m) => m.toLowerCase().includes(q))
  }, [models, modelFilter])

  const trimmed = value.trim()
  const globalLabel = defaultModel ? t('comp.model.globalNamed', { model: defaultModel }) : t('comp.model.global')
  const selectValue = !trimmed ? GLOBAL : models.includes(trimmed) ? trimmed : NONE

  async function fetchModels() {
    setListing(true)
    setListError('')
    try {
      const out = await api.listLlmModels({})
      if (out.ok) {
        setModels(out.models)
        if (!out.models.length) setListError(t('comp.model.emptyList'))
      } else {
        setModels([])
        setListError(out.error || t('comp.model.fetchFail'))
      }
    } catch (e) {
      setModels([])
      setListError(formatApiError(e, t('comp.model.fetchTimeout')))
    } finally {
      setListing(false)
    }
  }

  return (
    <div className={cn('space-y-2', className)}>
      <Label className="font-medium">{t('comp.model.label')}</Label>
      <p className="text-xs leading-relaxed text-muted-foreground">{projectModelHint()}</p>
      <Input
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        placeholder={defaultModel ? t('comp.model.phNamed', { model: defaultModel }) : t('comp.model.phGlobal')}
      />
      {models.length > 0 ? (
        <>
          {models.length > 20 ? (
            <Input
              value={modelFilter}
              onChange={(e) => setModelFilter(e.target.value)}
              placeholder={t('comp.model.filter', { n: models.length })}
            />
          ) : null}
          <Select
            value={selectValue}
            onValueChange={(next) => {
              if (next == null || next === NONE) return
              onValueChange(next === GLOBAL ? '' : next)
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue>{trimmed || globalLabel}</SelectValue>
            </SelectTrigger>
            <SelectContent alignItemWithTrigger={false} align="start" className="max-h-72 w-(--anchor-width)">
              <SelectItem value={GLOBAL}>{globalLabel}</SelectItem>
              <SelectItem value={NONE}>
                {t('comp.model.fromList', { shown: filteredModels.length, total: models.length })}
              </SelectItem>
              {filteredModels.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" disabled={listing} onClick={() => void fetchModels()}>
          {listing ? t('comp.model.fetching') : t('comp.model.fetch')}
        </Button>
        {listError ? <span className="text-xs text-red-300">{listError}</span> : null}
      </div>
    </div>
  )
}
