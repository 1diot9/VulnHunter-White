import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export const WORKER_HINT_MAX = 20000

export const WORKER_HINT_HINT =
  '可选。粘贴文本或上传 .txt / .md，作为额外人工提示注入启发式、快速扫描和历史漏洞绕过的每轮挖掘。不要用它改焦点；运行中可改，下一轮生效。'

export const WORKER_HINT_PLACEHOLDER =
  '例如：重点看后台导出与文件下载；忽略演示账号；鉴权以 JWT 过滤器为准。'

const HINT_FILE_RE = /\.(txt|md|markdown|text)$/i

function isHintFile(file: File): boolean {
  if (HINT_FILE_RE.test(file.name)) return true
  return Boolean(file.type) && file.type.startsWith('text/')
}

export function WorkerHintFields({
  value,
  onChange,
  disabled = false,
}: {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}) {
  const [fileError, setFileError] = useState('')
  const count = value.length

  async function onFile(file: File | null) {
    setFileError('')
    if (!file) return
    if (!isHintFile(file)) {
      setFileError('请上传 .txt 或 .md 文本文件')
      return
    }
    const raw = await file.text()
    if (raw.includes('\0')) {
      setFileError('文件不是文本')
      return
    }
    const text = raw.replace(/^\uFEFF/, '').trim()
    if (text.length > WORKER_HINT_MAX) {
      setFileError(`挖掘提示过长，最多 ${WORKER_HINT_MAX} 字`)
      return
    }
    onChange(text)
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Label htmlFor="worker-hint" className="font-medium">
          挖掘 Worker 提示
        </Label>
        <div className="flex items-center gap-2">
          <Label className="inline-flex h-7 cursor-pointer items-center justify-center rounded-lg border border-input px-2.5 text-[0.8rem] font-medium hover:bg-muted has-[:disabled]:pointer-events-none has-[:disabled]:opacity-50">
            上传文本
            <input
              type="file"
              accept=".txt,.md,.markdown,.text,text/plain,text/markdown"
              className="hidden"
              disabled={disabled}
              onChange={(e) => {
                void onFile(e.target.files?.[0] || null)
                e.target.value = ''
              }}
            />
          </Label>
          {value.trim() ? (
            <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => onChange('')}>
              清空
            </Button>
          ) : null}
        </div>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">{WORKER_HINT_HINT}</p>
      <Textarea
        id="worker-hint"
        value={value}
        onChange={(e) => {
          setFileError('')
          onChange(e.target.value)
        }}
        placeholder={WORKER_HINT_PLACEHOLDER}
        rows={5}
        disabled={disabled}
        maxLength={WORKER_HINT_MAX}
      />
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          {count}/{WORKER_HINT_MAX}
        </span>
        {fileError ? <span className="text-red-300">{fileError}</span> : null}
      </div>
    </div>
  )
}
