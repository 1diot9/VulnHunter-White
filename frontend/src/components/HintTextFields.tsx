import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export const HINT_TEXT_MAX = 20000

const HINT_FILE_RE = /\.(txt|md|markdown|text)$/i

function isHintFile(file: File): boolean {
  if (HINT_FILE_RE.test(file.name)) return true
  return Boolean(file.type) && file.type.startsWith('text/')
}

export function HintTextFields({
  id,
  label,
  hint,
  placeholder,
  value,
  onChange,
  disabled = false,
  maxLength = HINT_TEXT_MAX,
  tooLongMessage,
}: {
  id: string
  label: string
  hint: string
  placeholder: string
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  maxLength?: number
  tooLongMessage?: string
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
    if (text.length > maxLength) {
      setFileError(tooLongMessage || `${label}过长，最多 ${maxLength} 字`)
      return
    }
    onChange(text)
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Label htmlFor={id} className="font-medium">
          {label}
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
      <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>
      <Textarea
        id={id}
        value={value}
        onChange={(e) => {
          setFileError('')
          onChange(e.target.value)
        }}
        placeholder={placeholder}
        rows={5}
        disabled={disabled}
        maxLength={maxLength}
      />
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          {count}/{maxLength}
        </span>
        {fileError ? <span className="text-red-300">{fileError}</span> : null}
      </div>
    </div>
  )
}
