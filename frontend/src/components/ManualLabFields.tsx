import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export const MANUAL_LAB_HINT =
  '适用于需人工搭建的漏洞环境。填写地址/账号等说明后，审核时优先用该描述，不可达再回退 Docker 靶场。创建后也可在项目配置中补充，下一轮审核生效。'

export const MANUAL_LAB_PLACEHOLDER =
  '例如：靶场 http://127.0.0.1:8080 ，账号 admin/admin，登录入口 /login。也可补充路径、鉴权头等。'

export function ManualLabToggle({
  enabled,
  prompt,
  onEnabledChange,
  onPromptChange,
}: {
  enabled: boolean
  prompt: string
  onEnabledChange: (enabled: boolean) => void
  onPromptChange: (prompt: string) => void
}) {
  return (
    <div className="space-y-2">
      <Label className="items-start font-normal">
        <Checkbox
          className="mt-0.5"
          checked={enabled}
          onCheckedChange={(checked) => onEnabledChange(checked === true)}
        />
        <span className="min-w-0">
          <span className="font-medium">人工靶场</span>
          <span className="mt-0.5 block text-xs font-normal leading-relaxed text-muted-foreground">
            {MANUAL_LAB_HINT}
          </span>
        </span>
      </Label>
      {enabled ? (
        <Textarea
          value={prompt}
          onChange={(e) => onPromptChange(e.target.value)}
          placeholder={MANUAL_LAB_PLACEHOLDER}
          rows={4}
        />
      ) : null}
    </div>
  )
}
