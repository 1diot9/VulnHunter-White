import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

type MiningPathValue = {
  heuristicEnabled: boolean
  heuristicLite: boolean
  fastEnabled: boolean
  bypassEnabled: boolean
  unconstrainedEnabled: boolean
}

type Props = {
  heuristicEnabled: boolean
  heuristicLite?: boolean
  fastEnabled: boolean
  bypassEnabled?: boolean
  unconstrainedEnabled?: boolean
  onChange: (next: MiningPathValue) => void
  disabled?: boolean
}

export function MiningPathSelect({
  heuristicEnabled,
  heuristicLite = false,
  fastEnabled,
  bypassEnabled = false,
  unconstrainedEnabled = false,
  onChange,
  disabled = false,
}: Props) {
  const emit = (next: Partial<MiningPathValue>) =>
    onChange({
      heuristicEnabled,
      heuristicLite,
      fastEnabled,
      bypassEnabled,
      unconstrainedEnabled,
      ...next,
    })

  const othersOn = (except: 'heuristic' | 'fast' | 'bypass' | 'unconstrained') => {
    if (except !== 'heuristic' && heuristicEnabled) return true
    if (except !== 'fast' && fastEnabled) return true
    if (except !== 'bypass' && bypassEnabled) return true
    if (except !== 'unconstrained' && unconstrainedEnabled) return true
    return false
  }

  const setHeuristic = (next: boolean) => {
    if (!next && !othersOn('heuristic')) return
    emit({ heuristicEnabled: next, heuristicLite: next ? heuristicLite : false })
  }
  const setLite = (next: boolean) => {
    if (!heuristicEnabled) return
    emit({ heuristicLite: next })
  }
  const setFast = (next: boolean) => {
    if (!next && !othersOn('fast')) return
    emit({ fastEnabled: next })
  }
  const setBypass = (next: boolean) => {
    if (!next && !othersOn('bypass')) return
    emit({ bypassEnabled: next })
  }
  const setUnconstrained = (next: boolean) => {
    if (!next && !othersOn('unconstrained')) return
    emit({ unconstrainedEnabled: next })
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
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={unconstrainedEnabled}
          disabled={disabled}
          onCheckedChange={(checked) => setUnconstrained(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">无约束扫描</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            历史漏洞收集完毕后启动，固定 1 个 Worker。只注入代码地图与鉴权文档，不派发定权文件。始终走赏金闸门；Reviewer 判定前台洞达成 RCE 效果后结束本路径。
          </span>
        </span>
      </Label>
    </div>
  )
}
