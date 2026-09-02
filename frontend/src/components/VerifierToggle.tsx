import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const VERIFIER_HINT =
  'Reviewer 确认前台漏洞后，用 FOFA 搜索同款互联网目标。先按报告和 PoC 理解利用本质，优先跑原 PoC；没有可用 HTTP PoC 时按报告构造 payload，不跳过；失效时在同一条洞上调整利用方式再测。默认每轮搜 10 个，成功 3 个即结束；不足则保留已成功的并再搜下一轮，最多 5 轮（合计最多 50 个目标）。任意文件删除、DoS、SQL 增删改等会中断或篡改业务的漏洞需你确认后才测。需在设置中配置 FOFA Key。默认关闭。'

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
