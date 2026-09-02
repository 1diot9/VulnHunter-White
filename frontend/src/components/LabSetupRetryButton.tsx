import { useState } from 'react'
import { api, formatApiError, type Project } from '../api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/textarea'

type LabSetupRetryButtonProps = {
  project: Project
  onStarted?: () => void
}

export function LabSetupRetryButton({ project, onStarted }: LabSetupRetryButtonProps) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [userMessage, setUserMessage] = useState('')

  if (!project.lab_setup_retryable) return null

  const close = () => {
    if (busy) return
    setOpen(false)
    setError('')
    setUserMessage('')
  }

  async function confirm() {
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await api.retryLabSetup(project.id, userMessage.trim())
      setOpen(false)
      setUserMessage('')
      onStarted?.()
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        title="环境搭建重试用尽后，强制再跑一轮 Docker 靶场搭建"
        onClick={() => {
          setError('')
          setOpen(true)
        }}
      >
        续跑环境搭建
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>续跑 Docker 靶场搭建？</DialogTitle>
            <DialogDescription className="whitespace-pre-wrap leading-relaxed">
              上轮环境搭建因超时/重试用尽已结束，后续审核将仅静态验证。确认后将重置搭建状态并新开一轮
              「审核 → 环境搭建」对话；可选填写说明，指示 Agent 优先尝试的方向（例如已有 compose
              路径、端口、依赖镜像等）。不会清空 env/ 已有产物。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <label className="text-sm text-muted-foreground" htmlFor="lab-retry-message">
              续跑说明（可选）
            </label>
            <Textarea
              id="lab-retry-message"
              value={userMessage}
              onChange={(e) => setUserMessage(e.target.value)}
              placeholder="例如：优先用 src/docker-compose.yml，MySQL 用 3307 端口，应用监听 8080…"
              rows={4}
              disabled={busy}
            />
          </div>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              取消
            </Button>
            <Button type="button" disabled={busy} onClick={() => void confirm()}>
              {busy ? '启动中…' : '开始续跑'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
