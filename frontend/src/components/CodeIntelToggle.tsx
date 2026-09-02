import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const CODE_INTEL_HINT =
  '与侦察并列。勾选后用 CodeGraph 给 src/ 建调用图，供 Worker / Reviewer 查符号与调用。索引写在 src/.codegraph/，多次构建覆盖同一目录。失败会降级，不阻塞审计。默认关闭以省磁盘；中途开启后挖掘会等这次构建结束。关闭会删除该项目索引。'

export function CodeIntelToggle({
  enabled,
  onEnabledChange,
  disabled = false,
}: {
  enabled: boolean
  onEnabledChange: (enabled: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">代码库</p>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={enabled}
          disabled={disabled}
          onCheckedChange={(checked) => onEnabledChange(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">构建调用图</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {CODE_INTEL_HINT}
          </span>
        </span>
      </Label>
    </div>
  )
}
