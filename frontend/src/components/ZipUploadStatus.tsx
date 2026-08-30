import { useEffect, useState } from 'react'
import { Loader2Icon, UploadIcon } from 'lucide-react'
import { cn, formatBytes } from '@/lib/utils'

const UPLOAD_STATUS_MESSAGES = [
  '正在把源码包送往服务端…',
  '大文件可能需要几分钟，请勿关闭窗口',
  '上传完成后将自动开始导入与侦察',
  '解压与建索引将在后台进行，请稍候',
  '网络较慢时计时仍会继续，请耐心等待',
  '正在传输压缩包，马上就好…',
  '服务端收到文件后会立即创建审计项目',
  '传输中，请勿刷新或关闭此窗口',
  '完成后将自动刷新项目列表',
  '若长时间无响应，可检查磁盘空间与网络连接',
] as const

const MESSAGE_ROTATE_MS = 3_500

function pickUploadMessage(exclude?: string): string {
  const pool =
    exclude && UPLOAD_STATUS_MESSAGES.length > 1
      ? UPLOAD_STATUS_MESSAGES.filter((m) => m !== exclude)
      : UPLOAD_STATUS_MESSAGES
  return pool[Math.floor(Math.random() * pool.length)] ?? UPLOAD_STATUS_MESSAGES[0]
}

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${String(s).padStart(2, '0')}`
}

type Props = {
  file: File
  className?: string
}

export function ZipUploadStatus({ file, className }: Props) {
  const [elapsedSec, setElapsedSec] = useState(0)
  const [message, setMessage] = useState(() => pickUploadMessage())

  useEffect(() => {
    const started = Date.now()
    const tick = window.setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - started) / 1000))
    }, 1000)
    return () => window.clearInterval(tick)
  }, [file.name, file.size, file.lastModified])

  useEffect(() => {
    const rotate = window.setInterval(() => {
      setMessage((prev) => pickUploadMessage(prev))
    }, MESSAGE_ROTATE_MS)
    return () => window.clearInterval(rotate)
  }, [file.name, file.size, file.lastModified])

  return (
    <div
      className={cn(
        'rounded-lg border border-border/80 bg-card/60 px-4 py-3 shadow-sm',
        className,
      )}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="flex items-start gap-3">
        <div className="relative mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-full bg-primary/10">
          <UploadIcon className="size-4 text-primary/70" aria-hidden />
          <Loader2Icon
            className="absolute size-9 animate-spin text-primary/90"
            aria-hidden
          />
        </div>
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
            <p className="truncate text-sm font-medium text-foreground">
              正在上传 {file.name}
            </p>
            <span className="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">
              {formatElapsed(elapsedSec)}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            {formatBytes(file.size)}
          </p>
          <p
            key={message}
            className="min-h-[1.25rem] animate-in fade-in slide-in-from-bottom-1 duration-500 text-sm text-muted-foreground"
          >
            {message}
          </p>
          <div
            className="relative h-1.5 overflow-hidden rounded-full bg-muted"
            aria-hidden
          >
            <div className="upload-indeterminate-bar absolute inset-y-0 w-2/5 rounded-full bg-primary/85" />
          </div>
        </div>
      </div>
    </div>
  )
}
