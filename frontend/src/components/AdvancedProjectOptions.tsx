import { SlidersHorizontal } from 'lucide-react'
import { MaxTokenUsageField } from './MaxTokenUsageField'
import { ProjectModelSelect } from './ProjectModelSelect'
import { ReconHintFields } from './ReconHintFields'
import { WorkerHintFields } from './WorkerHintFields'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

export function advancedOptionLabels({
  llmModel,
  maxTokenUsage,
  workerHint,
  reconHint,
}: {
  llmModel: string
  maxTokenUsage: string
  workerHint: string
  reconHint: string
}): string[] {
  const items: string[] = []
  if (llmModel.trim()) items.push('项目模型')
  if (maxTokenUsage.trim() && maxTokenUsage.trim() !== '0') items.push('Token 上限')
  if (reconHint.trim()) items.push('Recon 提示')
  if (workerHint.trim()) items.push('挖掘提示')
  return items
}

export function AdvancedProjectOptions({
  open,
  onOpenChange,
  llmModel,
  onLlmModelChange,
  maxTokenUsage,
  onMaxTokenUsageChange,
  workerHint,
  onWorkerHintChange,
  reconHint,
  onReconHintChange,
  disabled = false,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  llmModel: string
  onLlmModelChange: (value: string) => void
  maxTokenUsage: string
  onMaxTokenUsageChange: (value: string) => void
  workerHint: string
  onWorkerHintChange: (value: string) => void
  reconHint: string
  onReconHintChange: (value: string) => void
  disabled?: boolean
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="z-[60] max-h-[90vh] overflow-y-auto sm:max-w-lg"
        overlayClassName="z-[60]"
        showCloseButton={!disabled}
      >
        <DialogHeader>
          <DialogTitle>高级选项</DialogTitle>
          <DialogDescription>
            可选。项目模型、Token 上限、Recon 提示与挖掘 Worker 提示不影响挖掘路径和验证方式；下一轮 Agent 生效。
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <ProjectModelSelect value={llmModel} onValueChange={onLlmModelChange} />
          <MaxTokenUsageField value={maxTokenUsage} onChange={onMaxTokenUsageChange} disabled={disabled} />
          <ReconHintFields value={reconHint} onChange={onReconHintChange} disabled={disabled} />
          <WorkerHintFields value={workerHint} onChange={onWorkerHintChange} disabled={disabled} />
        </div>
        <DialogFooter>
          <DialogClose render={<Button type="button" disabled={disabled} />}>完成</DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function AdvancedProjectOptionsButton({
  onClick,
  llmModel,
  maxTokenUsage,
  workerHint,
  reconHint,
  disabled = false,
}: {
  onClick: () => void
  llmModel: string
  maxTokenUsage: string
  workerHint: string
  reconHint: string
  disabled?: boolean
}) {
  const configured = advancedOptionLabels({ llmModel, maxTokenUsage, workerHint, reconHint })

  return (
    <div className="space-y-2">
      <Button
        type="button"
        variant="outline"
        disabled={disabled}
        className="w-full justify-start"
        onClick={onClick}
      >
        <SlidersHorizontal />
        高级选项
        {configured.length ? (
          <span className="ml-auto text-xs font-normal text-muted-foreground">已设置 {configured.length} 项</span>
        ) : null}
      </Button>
      <p className="text-xs leading-relaxed text-muted-foreground">
        项目模型、Token 上限、Recon 提示与挖掘 Worker 提示。
        {configured.length ? ` 已设置：${configured.join('、')}。` : ''}
      </p>
    </div>
  )
}
