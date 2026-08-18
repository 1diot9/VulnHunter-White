import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const DYNAMIC_VERIFY_HINT =
  'Reviewer 搭建 Docker 靶场（或使用人工靶场），用 HTTP PoC / debug MCP 动态复现后再确认。默认关闭，只做静态复核；静态已能证明默认可利用时以 static_only 入库。'

export function DynamicVerifyToggle({
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
        <span className="font-medium">动态验证</span>
        <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
          {DYNAMIC_VERIFY_HINT}
        </span>
      </span>
    </Label>
  )
}
