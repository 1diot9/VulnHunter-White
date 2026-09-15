import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { t } from '@/i18n/t'
import { cn, formatAttackSurface } from '@/lib/utils'

type AttackSurfaceBadgeProps = {
  attackSurface: string | null | undefined
  requiredAccount?: string | null
  nested?: boolean
}

function attackSurfaceTooltip(
  attackSurface: string | null | undefined,
  requiredAccount: string | null | undefined,
): string | null {
  if (attackSurface === 'frontend') {
    return t('surface.tip.frontend')
  }
  if (attackSurface === 'backend') {
    if (requiredAccount === 'admin') {
      return t('surface.tip.backendAdmin')
    }
    if (requiredAccount === 'user') {
      return t('surface.tip.backendUser')
    }
    return t('surface.tip.backend')
  }
  return null
}

export default function AttackSurfaceBadge({
  attackSurface,
  requiredAccount,
  nested,
}: AttackSurfaceBadgeProps) {
  const label = formatAttackSurface(attackSurface, requiredAccount)
  const tip = attackSurfaceTooltip(attackSurface, requiredAccount)
  if (!label) return null

  const badge = (
    <Badge className={cn(nested && 'h-4 px-1.5 text-[10px] cursor-help', !nested && 'cursor-help')} variant="info">
      {label}
    </Badge>
  )

  if (!tip) return badge

  return (
    <Tooltip>
      <TooltipTrigger render={<span className="inline-flex cursor-help" />}>{badge}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-sm text-left leading-relaxed whitespace-pre-line">
        {tip}
      </TooltipContent>
    </Tooltip>
  )
}
