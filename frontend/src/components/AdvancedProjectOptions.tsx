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
import { useI18n } from '@/i18n'
import { t } from '@/i18n/t'

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
  if (llmModel.trim()) items.push(t('comp.adv.item.model'))
  if (maxTokenUsage.trim() && maxTokenUsage.trim() !== '0') items.push(t('comp.adv.item.token'))
  if (reconHint.trim()) items.push(t('comp.adv.item.recon'))
  if (workerHint.trim()) items.push(t('comp.adv.item.worker'))
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
  const { t } = useI18n()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="z-[60] max-h-[90vh] overflow-y-auto sm:max-w-lg"
        overlayClassName="z-[60]"
        showCloseButton={!disabled}
      >
        <DialogHeader>
          <DialogTitle>{t('comp.adv.title')}</DialogTitle>
          <DialogDescription>{t('comp.adv.body')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <ProjectModelSelect value={llmModel} onValueChange={onLlmModelChange} />
          <MaxTokenUsageField value={maxTokenUsage} onChange={onMaxTokenUsageChange} disabled={disabled} />
          <ReconHintFields value={reconHint} onChange={onReconHintChange} disabled={disabled} />
          <WorkerHintFields value={workerHint} onChange={onWorkerHintChange} disabled={disabled} />
        </div>
        <DialogFooter>
          <DialogClose render={<Button type="button" disabled={disabled} />}>{t('common.done')}</DialogClose>
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
  const { t, locale } = useI18n()
  const configured = advancedOptionLabels({ llmModel, maxTokenUsage, workerHint, reconHint })
  const listJoin = locale === 'zh' ? '、' : ', '

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
        {t('comp.adv.title')}
        {configured.length ? (
          <span className="ml-auto text-xs font-normal text-muted-foreground">
            {t('comp.adv.configured', { n: configured.length })}
          </span>
        ) : null}
      </Button>
      <p className="text-xs leading-relaxed text-muted-foreground">
        {t('comp.adv.summary')}
        {configured.length ? t('comp.adv.setList', { items: configured.join(listJoin) }) : ''}
      </p>
    </div>
  )
}
