import type { WeightExt } from '../api'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export function WeightExtBadges({
  exts,
  className,
}: {
  exts?: WeightExt[] | null
  className?: string
}) {
  if (!exts?.length) return null
  return (
    <div className={cn('flex flex-wrap items-center gap-1.5', className)}>
      <span className="text-xs text-muted-foreground">定权扩展名</span>
      {exts.map((item) => (
        <Badge
          key={item.ext}
          variant={item.agent_added ? 'info' : 'outline'}
          title={
            item.agent_added
              ? `Agent 追加 · ${item.files} 个文件`
              : `默认源码扩展名 · ${item.files} 个文件`
          }
        >
          {item.ext}
          {item.agent_added ? <span className="font-normal opacity-80">Agent</span> : null}
        </Badge>
      ))}
    </div>
  )
}
