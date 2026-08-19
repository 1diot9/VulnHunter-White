import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const ATTACK_CHAIN_HINT =
  '挖掘与审核都结束后，根据本项目已确认漏洞尝试多步串联利用，扩大危害。已确认洞少于 2 条时自动跳过。不执行 PoC、不打靶场。默认关闭。'

export function AttackChainToggle({
  enabled,
  onEnabledChange,
}: {
  enabled: boolean
  onEnabledChange: (enabled: boolean) => void
}) {
  return (
    <Label className="items-start font-normal">
      <Checkbox
        className="mt-0.5"
        checked={enabled}
        onCheckedChange={(checked) => onEnabledChange(checked === true)}
      />
      <span className="min-w-0">
        <span className="font-medium">攻击链串联</span>
        <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
          {ATTACK_CHAIN_HINT}
        </span>
      </span>
    </Label>
  )
}
