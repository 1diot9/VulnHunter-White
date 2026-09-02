import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export const CODE_INTEL_HINT =
  '用 CodeGraph 给 src/ 建调用图，供挖掘 Worker 和 Reviewer 查符号与调用关系。索引写在项目 src/.codegraph/，体积较大，默认关闭。不开启时挖掘只等侦察完成，仍用 Read / Grep。失败会降级，不阻塞审计。暂停或完成后可再开；关闭会删除该项目索引以释放磁盘。'

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
    <Label className="items-start font-normal">
      <Checkbox
        className="mt-0.5"
        checked={enabled}
        disabled={disabled}
        onCheckedChange={(checked) => onEnabledChange(checked === true)}
      />
      <span className="min-w-0">
        <span className="font-medium">代码库（调用图）</span>
        <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
          {CODE_INTEL_HINT}
        </span>
      </span>
    </Label>
  )
}
