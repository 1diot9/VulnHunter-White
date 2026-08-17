import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const VERIFIER_HINT =
  'Reviewer 确认前台漏洞后，用 FOFA 搜索同款互联网目标并按报告复测。默认搜 10 个，任一成功即结束。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞不会测互联网目标。需在设置中配置 FOFA Key。默认关闭。'

export function VerifierToggle({
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
        <span className="font-medium">Verifier（互联网验证）</span>
        <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
          {VERIFIER_HINT}
        </span>
      </span>
    </Label>
  )
}
