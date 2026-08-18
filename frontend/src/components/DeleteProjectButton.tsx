import { useState } from 'react'
import { api } from '../api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

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
  const [error, setError] = useState('')

  const close = () => {
    if (busy) return
    setOpen(false)
    setError('')
  }

  async function confirmDelete() {
    setBusy(true)
    setError('')
    try {
      await api.deleteProject(projectId)
      setOpen(false)
      onDeleted?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        variant={variant}
        size={size}
        onClick={() => {
          setError('')
          setOpen(true)
        }}
      >
        删除
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close()
          else setOpen(true)
        }}
      >
        <DialogContent showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>删除项目</DialogTitle>
            <DialogDescription>
              将永久删除「{projectName}」及其源码工作区、阶段日志和漏洞报告，此操作不可恢复。请再次确认。
            </DialogDescription>
          </DialogHeader>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={close}>
              取消
            </Button>
            <Button variant="destructive" disabled={busy} onClick={confirmDelete}>
              {busy ? '删除中…' : '确认删除'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
