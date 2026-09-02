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

type SubId = 'map' | 'old_vulns'

const SUB_META: Record<
  SubId,
  { title: string; description: string; confirm: string }
> = {
  map: {
    title: '更新代码地图与鉴权文档？',
    description:
      '将在保留现有 docs/code-map.md、docs/auth.md 的前提下，按「地图/鉴权」原流程再跑一轮 Agent，对照源码复核并写回更新。不会清空已有文档，也不会重跑扩展名、历史漏洞或盖章。进度与日志出现在「侦察 → 地图/鉴权」下的新一轮对话中。',
    confirm: '开始更新',
  },
  old_vulns: {
    title: '更新历史漏洞文档？',
    description:
      '将在保留 docs/old-vulns/ 已有条目的前提下，按「历史漏洞」原流程再跑一轮（爬虫落盘 → WebSearch 补漏），用于补漏或刷新索引。不会删除已落盘的历史漏洞文档，也不会重跑地图/鉴权或盖章。进度与日志出现在「侦察 → 历史漏洞」下的新一轮对话中。',
    confirm: '开始更新',
  },
}

type ReconDocRerunButtonsProps = {
  project: Project
  onStarted?: (subId: SubId) => void
}

export function ReconDocRerunButtons({ project, onStarted }: ReconDocRerunButtonsProps) {
  const [pending, setPending] = useState<SubId | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const mapDone = Boolean(project.recon_subphases?.find((s) => s.id === 'map')?.done)
  const oldDone = Boolean(project.recon_subphases?.find((s) => s.id === 'old_vulns')?.done)
  if (!mapDone && !oldDone) return null

  const meta = pending ? SUB_META[pending] : null

  const close = () => {
    if (busy) return
    setPending(null)
    setError('')
  }

  async function confirm() {
    if (!pending || busy) return
    const sub = pending
    setBusy(true)
    setError('')
    try {
      await api.rerunReconSubphase(project.id, sub)
      setPending(null)
      onStarted?.(sub)
    } catch (e) {
      setError(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="inline-flex flex-wrap items-center gap-1.5 rounded-lg border border-dashed border-slate-600/80 bg-slate-900/40 px-1.5 py-1">
        <span className="px-1 text-[11px] text-slate-500">侦察文档</span>
        {mapDone ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 text-slate-300"
            disabled={busy}
            title="保留原文档，再跑一轮地图/鉴权以更新"
            onClick={() => {
              setError('')
              setPending('map')
            }}
          >
            更新地图/鉴权
          </Button>
        ) : null}
        {oldDone ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 text-slate-300"
            disabled={busy}
            title="保留原文档，再跑一轮历史漏洞收集以更新"
            onClick={() => {
              setError('')
              setPending('old_vulns')
            }}
          >
            更新历史漏洞
          </Button>
        ) : null}
      </div>
      <Dialog
        open={pending != null}
        onOpenChange={(next) => {
          if (!next) close()
        }}
      >
        <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
          <DialogHeader>
            <DialogTitle>{meta?.title}</DialogTitle>
            <DialogDescription className="whitespace-pre-wrap leading-relaxed">
              {meta?.description}
            </DialogDescription>
          </DialogHeader>
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={close}>
              取消
            </Button>
            <Button type="button" disabled={busy} onClick={() => void confirm()}>
              {busy ? '启动中…' : meta?.confirm ?? '确认'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
