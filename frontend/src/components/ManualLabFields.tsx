import { useEffect, useState } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'

export const MANUAL_LAB_HINT =
  '适用于需人工搭建的漏洞环境。开启后填写地址/账号等说明，审核漏洞开始时注入；审计运行中也可修改，下一轮审核生效。'

export const MANUAL_LAB_PLACEHOLDER =
  '例如：靶场 http://127.0.0.1:8080 ，账号 admin/admin，登录入口 /login。也可补充路径、鉴权头等。'

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
  return (
    <div className="space-y-2">
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={enabled}
          onCheckedChange={(checked) => onEnabledChange(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">人工靶场</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {MANUAL_LAB_HINT}
          </span>
        </span>
      </Label>
      {enabled ? (
        <Textarea
          value={prompt}
          onChange={(e) => onPromptChange(e.target.value)}
          placeholder={MANUAL_LAB_PLACEHOLDER}
          rows={4}
        />
      ) : null}
    </div>
  )
}

export function ManualLabPromptEditor({
  prompt,
  onSave,
}: {
  prompt: string
  onSave: (prompt: string) => Promise<void>
}) {
  const [draft, setDraft] = useState(prompt)
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!dirty) setDraft(prompt)
  }, [prompt, dirty])

  async function save() {
    setSaving(true)
    setError('')
    try {
      await onSave(draft)
      setDirty(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-2 rounded-lg border border-input p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-sm font-medium">人工靶场</p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
            审核开始时注入下列环境说明。保存后对下一轮审核生效。
          </p>
        </div>
        <Button type="button" size="sm" disabled={saving || !dirty} onClick={() => void save()}>
          {saving ? '保存中…' : '保存'}
        </Button>
      </div>
      <Textarea
        value={draft}
        onChange={(e) => {
          setDraft(e.target.value)
          setDirty(true)
        }}
        placeholder={MANUAL_LAB_PLACEHOLDER}
        rows={4}
      />
      {error ? <p className="text-xs text-red-300">{error}</p> : null}
    </div>
  )
}
