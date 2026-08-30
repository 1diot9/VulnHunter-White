import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
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
    return '前台漏洞：公开或未登录即可打到。'
  }
  if (attackSurface === 'backend') {
    if (requiredAccount === 'admin') {
      return '后台漏洞：须具备管理员权限才能利用。'
    }
    if (requiredAccount === 'user') {
      return '后台漏洞：须具备普通应用内账号（低权限用户）才能利用。'
    }
    return '后台漏洞：须具备相应应用内账号才能利用。'
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
