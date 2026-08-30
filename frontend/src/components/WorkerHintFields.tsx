import { HINT_TEXT_MAX, HintTextFields } from './HintTextFields'

export const WORKER_HINT_MAX = HINT_TEXT_MAX

export const WORKER_HINT_HINT =
  '可选。粘贴文本或上传 .txt / .md，作为额外人工提示注入启发式、快速扫描和历史漏洞绕过的每轮挖掘。不要用它改焦点；运行中可改，下一轮生效。'

export const WORKER_HINT_PLACEHOLDER =
  '例如：重点看后台导出与文件下载；忽略演示账号；鉴权以 JWT 过滤器为准。'

export function WorkerHintFields({
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
      id="worker-hint"
      label="挖掘 Worker 提示"
      hint={WORKER_HINT_HINT}
      placeholder={WORKER_HINT_PLACEHOLDER}
      value={value}
      onChange={onChange}
      disabled={disabled}
      tooLongMessage={`挖掘提示过长，最多 ${WORKER_HINT_MAX} 字`}
    />
  )
}
