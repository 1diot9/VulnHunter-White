import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

type MiningPathValue = {
  heuristicEnabled: boolean
  heuristicLite: boolean
  fastEnabled: boolean
  bypassEnabled: boolean
}

type Props = {
  heuristicEnabled: boolean
  heuristicLite?: boolean
  fastEnabled: boolean
  bypassEnabled?: boolean
  onChange: (next: MiningPathValue) => void
  disabled?: boolean
}

export function MiningPathSelect({
  heuristicEnabled,
  heuristicLite = false,
  fastEnabled,
  bypassEnabled = false,
  onChange,
  disabled = false,
}: Props) {
  const setHeuristic = (next: boolean) => {
    if (!next && !fastEnabled && !bypassEnabled) return
    onChange({ heuristicEnabled: next, heuristicLite, fastEnabled, bypassEnabled })
  }
  const setLite = (next: boolean) => {
    if (!heuristicEnabled) return
    onChange({ heuristicEnabled, heuristicLite: next, fastEnabled, bypassEnabled })
  }
  const setFast = (next: boolean) => {
    if (!next && !heuristicEnabled && !bypassEnabled) return
    onChange({ heuristicEnabled, heuristicLite, fastEnabled: next, bypassEnabled })
  }
  const setBypass = (next: boolean) => {
    if (!next && !heuristicEnabled && !fastEnabled) return
    onChange({ heuristicEnabled, heuristicLite, fastEnabled, bypassEnabled: next })
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">挖掘路径</p>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={heuristicEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setHeuristic(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">启发式挖掘</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            历史漏洞收集完毕后按文件定权，Worker 从高权未审计文件沿 source→sink 挖洞。缺鉴权、IDOR、业务逻辑仍靠这条。
          </span>
        </span>
      </Label>
      <Label className="items-start pl-6 font-normal">
        <Checkbox
          className="mt-0.5"
          checked={heuristicEnabled && heuristicLite}
          disabled={disabled || !heuristicEnabled}
          onCheckedChange={(checked) => setLite(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">轻量版</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            只把权重 100 的文件作为入口；更低权重不阻塞完成。默认关闭，挖完全部定权文件。
          </span>
        </span>
      </Label>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={fastEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setFast(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">快速扫描</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            Recon 后 Semgrep 匹配 Sink，代码硬过滤后再由 Agent 冻结约 60 条，Fast Worker 按条从 Sink 回推。覆盖 SAST Sink，不替代启发式。
          </span>
        </span>
      </Label>
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={bypassEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setBypass(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">历史漏洞绕过</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            历史漏洞收集完毕后，每轮注入一条历史漏洞文档，尝试绕过补丁、打出变体，或确认未修复洞仍可利用。
          </span>
        </span>
      </Label>
    </div>
  )
}
