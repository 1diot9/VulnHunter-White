import { useState } from 'react'
import { api, type Project } from '../api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'

const RESET_OK_STATUSES = new Set(['paused', 'completed', 'cancelled', 'error'])

type ResetProgressButtonProps = {
  project: Project
  onReset?: (project: Project) => void
}

export function ResetProgressButton({ project, onReset }: ResetProgressButtonProps) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [acked, setAcked] = useState(false)
  const [error, setError] = useState('')
  const allowed = RESET_OK_STATUSES.has(project.status)

  const close = () => {
    if (busy) return
    setOpen(false)
    setAcked(false)
    setError('')
  }

  function openDialog() {
    if (!allowed) return
    setError('')
    setAcked(false)
    setOpen(true)
  }

  async function confirmReset() {
    if (!acked || busy) return
    setBusy(true)
    setError('')
    try {
      const next = await api.resetProgress(project.id)
      setOpen(false)
      setAcked(false)
      onReset?.(next)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="warning"
        disabled={!allowed}
        title={allowed ? '重置启发式挖掘进度，保留快速扫描、历史漏洞绕过、无约束扫描、漏洞与侦察文档' : '请先全部暂停，再重置挖掘进度'}
        onClick={openDialog}
      >
        重置进度
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (next) openDialog()
          else close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>确认重置启发式挖掘进度</DialogTitle>
            <DialogDescription>
              将清空「{project.name}」的启发式已审计文件标记、启发式轮次报告和 Worker 检查点。快速扫描 Sink 队列、历史漏洞绕过进度、无约束扫描进度、Semgrep 产物与冻结名单保留。漏洞产出、侦察文档、定权/跳过标记和环境搭建会保留。重置后项目保持暂停。请再次确认。
            </DialogDescription>
          </DialogHeader>
          <Label className="items-start font-normal">
            <Checkbox
              className="mt-0.5"
              checked={acked}
              disabled={busy}
              onCheckedChange={(checked) => setAcked(checked === true)}
            />
            <span className="min-w-0 text-sm leading-relaxed">
              我已了解，确认清空启发式挖掘进度（快速扫描、历史漏洞绕过、无约束扫描、漏洞与侦察文档不受影响）
            </span>
          </Label>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              取消
            </Button>
            <Button
              type="button"
              variant="warning"
              disabled={busy || !acked}
              onClick={() => void confirmReset()}
            >
              {busy ? '重置中…' : '确认重置'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
