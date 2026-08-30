import { HINT_TEXT_MAX, HintTextFields } from './HintTextFields'

export const RECON_HINT_MAX = HINT_TEXT_MAX

export const RECON_HINT_HINT =
  '可选。粘贴文本或上传 .txt / .md，作为额外人工提示注入侦察各小阶段（地图/鉴权、扩展名、历史漏洞、盖章）。不要用它跳过门闩任务；运行中可改，下一轮生效。'

export const RECON_HINT_PLACEHOLDER =
  '例如：重点画 SSO 与后台管理路由；忽略演示模块；鉴权以 JWT 过滤器为准。'

export function ReconHintFields({
  value,
  onChange,
  disabled = false,
}: {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
}) {
  return (
    <HintTextFields
      id="recon-hint"
      label="Recon 提示"
      hint={RECON_HINT_HINT}
      placeholder={RECON_HINT_PLACEHOLDER}
      value={value}
      onChange={onChange}
      disabled={disabled}
      tooLongMessage={`Recon 提示过长，最多 ${RECON_HINT_MAX} 字`}
    />
  )
}
