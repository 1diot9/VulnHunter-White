import type { WeightExt } from '../api'
import { Badge } from '@/components/ui/badge'
import { useI18n } from '@/i18n'
import { cn } from '@/lib/utils'

export function WeightExtBadges({
  exts,
  className,
}: {
  exts?: WeightExt[] | null
  className?: string
}) {
  const { t } = useI18n()
  if (!exts?.length) return null
  return (
    <div className={cn('flex flex-wrap items-center gap-1.5', className)}>
      <span className="text-xs text-muted-foreground">{t('comp.weight.label')}</span>
      {exts.map((item) => (
        <Badge
          key={item.ext}
          variant={item.agent_added ? 'info' : 'outline'}
          title={
            item.agent_added
              ? t('comp.weight.agent', { n: item.files })
              : t('comp.weight.default', { n: item.files })
          }
        >
          {item.ext}
          {item.agent_added ? <span className="font-normal opacity-80">Agent</span> : null}
        </Badge>
      ))}
    </div>
  )
}
