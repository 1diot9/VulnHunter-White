import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'

const GLOBAL = '__global__'
const NONE = '__none__'

export const PROJECT_MODEL_HINT =
  '不选则使用设置里的全局模型。保存后对下一轮 Agent（侦察 / 挖掘 / 审核 / 验证）生效。'

export function ProjectModelSelect({
  value,
  onValueChange,
  className,
}: {
  value: string
  onValueChange: (value: string) => void
  className?: string
}) {
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
  const globalLabel = defaultModel ? `使用全局默认（${defaultModel}）` : '使用全局默认'
  const selectValue = !trimmed ? GLOBAL : models.includes(trimmed) ? trimmed : NONE

  async function fetchModels() {
    setListing(true)
    setListError('')
    try {
      const out = await api.listLlmModels({})
      if (out.ok) {
        setModels(out.models)
        if (!out.models.length) setListError('清单为空')
      } else {
        setModels([])
        setListError(out.error || '拉取失败')
      }
    } catch (e) {
      setModels([])
      setListError(String(e))
    } finally {
      setListing(false)
    }
  }

  return (
    <div className={cn('space-y-2', className)}>
      <Label className="font-medium">项目模型</Label>
      <p className="text-xs leading-relaxed text-muted-foreground">{PROJECT_MODEL_HINT}</p>
      <Input
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        placeholder={defaultModel ? `留空则用 ${defaultModel}` : '留空则使用全局模型'}
      />
      {models.length > 0 ? (
        <>
          {models.length > 20 ? (
            <Input
              value={modelFilter}
              onChange={(e) => setModelFilter(e.target.value)}
              placeholder={`筛选 ${models.length} 个模型…`}
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
              <SelectItem value={NONE}>从清单选择（{filteredModels.length}/{models.length}）…</SelectItem>
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
          {listing ? '拉取中…' : '拉取模型清单'}
        </Button>
        {listError ? <span className="text-xs text-red-300">{listError}</span> : null}
      </div>
    </div>
  )
}
