import { useState } from 'react'
import { api, formatApiError } from '../api'
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

type DeleteProjectButtonProps = {
  projectId: number
  projectName: string
  onDeleted?: () => void
  variant?: 'destructive' | 'outline'
  size?: 'default' | 'sm'
}

export function DeleteProjectButton({
  projectId,
  projectName,
  onDeleted,
  variant = 'destructive',
  size = 'default',
}: DeleteProjectButtonProps) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [acked, setAcked] = useState(false)
  const [error, setError] = useState('')

  const close = () => {
    if (busy) return
    setOpen(false)
    setAcked(false)
    setError('')
  }

  function openDialog() {
    setError('')
    setAcked(false)
    setOpen(true)
  }

  async function confirmDelete() {
    if (!acked || busy) return
    setBusy(true)
    setError('')
    try {
      await api.deleteProject(projectId)
      setOpen(false)
      setAcked(false)
      onDeleted?.()
    } catch (e) {
      setError(formatApiError(e, '删除项目超时，工作区较大时请稍后重试。'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        type="button"
        variant={variant}
        size={size}
        onClick={openDialog}
      >
        删除
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
            <DialogTitle>确认删除项目</DialogTitle>
            <DialogDescription>
              将永久删除「{projectName}」及其源码工作区、阶段日志和漏洞报告，此操作不可恢复。请再次确认。
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
              我已了解，确认永久删除该项目及其全部数据
            </span>
          </Label>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              取消
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={busy || !acked}
              onClick={() => void confirmDelete()}
            >
              {busy ? '删除中…' : '确认删除'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
