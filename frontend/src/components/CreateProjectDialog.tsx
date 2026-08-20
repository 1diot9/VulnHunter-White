import { useEffect, useState } from 'react'
import { api, type CustomAuditMode } from '../api'
import { AuditModeSelect } from './AuditModeSelect'
import { AttackChainToggle } from './AttackChainToggle'
import { AuditFlowPreview } from './AuditFlowPreview'
import { DynamicVerifyToggle, type DynamicVerifyMode } from './DynamicVerifyToggle'
import { ManualLabToggle } from './ManualLabFields'
import { MiningPathSelect } from './MiningPathSelect'
import { ProjectModelSelect } from './ProjectModelSelect'
import { VerifierToggle } from './VerifierToggle'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { AuditMode } from '@/lib/utils'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void | Promise<void>
}

export function CreateProjectDialog({ open, onOpenChange, onCreated }: Props) {
  const [url, setUrl] = useState('')
  const [auditMode, setAuditMode] = useState<AuditMode>('bounty')
  const [customModes, setCustomModes] = useState<CustomAuditMode[]>([])
  const [customModeId, setCustomModeId] = useState<number | null>(null)
  const [manualLab, setManualLab] = useState(false)
  const [manualLabPrompt, setManualLabPrompt] = useState('')
  const [dynamicVerifyMode, setDynamicVerifyMode] = useState<DynamicVerifyMode>('off')
  const [verifierEnabled, setVerifierEnabled] = useState(false)
  const [attackChainEnabled, setAttackChainEnabled] = useState(false)
  const [heuristicEnabled, setHeuristicEnabled] = useState(true)
  const [heuristicLite, setHeuristicLite] = useState(false)
  const [fastEnabled, setFastEnabled] = useState(false)
  const [bypassEnabled, setBypassEnabled] = useState(false)
  const [llmModel, setLlmModel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const dynamicVerifyEnabled = dynamicVerifyMode !== 'off'
  const labMode = dynamicVerifyMode === 'lab'
  const selectedCustomName = customModes.find((m) => m.id === customModeId)?.name

  useEffect(() => {
    if (!open) return
    setError('')
    api.listCustomAuditModes().then(setCustomModes).catch(() => setCustomModes([]))
  }, [open])

  const close = () => {
    if (busy) return
    onOpenChange(false)
  }

  function createOpts() {
    return {
      custom_audit_mode_id: auditMode === 'custom' ? customModeId : null,
      manual_lab: labMode && manualLab,
      manual_lab_prompt: labMode && manualLab ? manualLabPrompt : '',
      verifier_enabled: verifierEnabled,
      attack_chain_enabled: attackChainEnabled,
      dynamic_verify_enabled: dynamicVerifyEnabled,
      dynamic_verify_mode: dynamicVerifyMode,
      heuristic_enabled: heuristicEnabled,
      heuristic_lite: heuristicLite,
      fast_enabled: fastEnabled,
      bypass_enabled: bypassEnabled,
      llm_model: llmModel,
    }
  }

  async function createGithub() {
    if (!url.trim()) return
    if (auditMode === 'custom' && customModeId == null) {
      setError('请先选择自定义审计模式（可在设置页创建）')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.createGithub(url.trim(), '', auditMode, createOpts())
      setUrl('')
      onOpenChange(false)
      await onCreated()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function onZip(file: File | null) {
    if (!file) return
    if (auditMode === 'custom' && customModeId == null) {
      setError('请先选择自定义审计模式（可在设置页创建）')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.uploadZip(file, '', auditMode, createOpts())
      onOpenChange(false)
      await onCreated()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) onOpenChange(true)
        else close()
      }}
    >
      <DialogContent
        className="flex max-h-[min(90vh,56rem)] w-full max-w-[calc(100%-2rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-5xl"
        showCloseButton={!busy}
      >
        <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
          <DialogTitle>创建项目</DialogTitle>
          <DialogDescription>
            导入 GitHub 仓库或源码 zip。可选择赏金/全量/自定义模式、挖掘路径、验证方式与项目模型。
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)] xl:items-start">
            <div className="space-y-3">
              <AuditModeSelect
                value={auditMode}
                customModeId={customModeId}
                customModes={customModes}
                customModeName={selectedCustomName}
                onValueChange={setAuditMode}
                onCustomModeIdChange={setCustomModeId}
              />
              <ProjectModelSelect value={llmModel} onValueChange={setLlmModel} />
              <MiningPathSelect
                heuristicEnabled={heuristicEnabled}
                heuristicLite={heuristicLite}
                fastEnabled={fastEnabled}
                bypassEnabled={bypassEnabled}
                onChange={({ heuristicEnabled: nextH, heuristicLite: nextL, fastEnabled: nextF, bypassEnabled: nextB }) => {
                  setHeuristicEnabled(nextH)
                  setHeuristicLite(nextL)
                  setFastEnabled(nextF)
                  setBypassEnabled(nextB)
                }}
              />
              <DynamicVerifyToggle mode={dynamicVerifyMode} onModeChange={setDynamicVerifyMode} />
              {labMode ? (
                <ManualLabToggle
                  enabled={manualLab}
                  prompt={manualLabPrompt}
                  onEnabledChange={setManualLab}
                  onPromptChange={setManualLabPrompt}
                />
              ) : null}
              <VerifierToggle enabled={verifierEnabled} onEnabledChange={setVerifierEnabled} />
              <AttackChainToggle enabled={attackChainEnabled} onEnabledChange={setAttackChainEnabled} />
            </div>
            <AuditFlowPreview
              className="xl:sticky xl:top-0"
              auditMode={auditMode}
              dynamicVerifyEnabled={dynamicVerifyEnabled}
              dynamicVerifyMode={dynamicVerifyMode}
              manualLab={manualLab}
              verifierEnabled={verifierEnabled}
              attackChainEnabled={attackChainEnabled}
              heuristicEnabled={heuristicEnabled}
              heuristicLite={heuristicLite}
              fastEnabled={fastEnabled}
              bypassEnabled={bypassEnabled}
            />
          </div>
        </div>
        <div className="shrink-0 space-y-3 border-t border-border bg-muted/50 px-5 py-4">
          {error ? <p className="text-sm text-red-300">{error}</p> : null}
          <div className="grid w-full gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto]">
            <Input
              className="w-full"
              placeholder="https://github.com/owner/repo"
              value={url}
              disabled={busy}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void createGithub()
              }}
            />
            <Button disabled={busy} onClick={() => void createGithub()}>
              从 GitHub 创建
            </Button>
            <Label className="inline-flex h-8 cursor-pointer items-center justify-center rounded-lg border border-input px-3 text-sm font-medium hover:bg-muted">
              上传 Zip
              <Input
                type="file"
                accept=".zip"
                className="hidden"
                disabled={busy}
                onChange={(e) => {
                  void onZip(e.target.files?.[0] || null)
                  e.target.value = ''
                }}
              />
            </Label>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
