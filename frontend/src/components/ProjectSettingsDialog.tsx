import { useEffect, useState } from 'react'
import { api, type Project } from '../api'
import { DynamicVerifyToggle, normalizeDynamicVerifyMode, type DynamicVerifyMode } from './DynamicVerifyToggle'
import { MANUAL_LAB_HINT, MANUAL_LAB_PLACEHOLDER } from './ManualLabFields'
import { MiningPathSelect } from './MiningPathSelect'
import { ProjectModelSelect } from './ProjectModelSelect'
import { VerifierToggle } from './VerifierToggle'
import { AttackChainToggle } from './AttackChainToggle'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'

export function ProjectSettingsButton({
  project,
  onSaved,
}: {
  project: Project
  onSaved: (project: Project) => void
}) {
  const [open, setOpen] = useState(false)
  const [prompt, setPrompt] = useState(project.manual_lab_prompt || '')
  const [dynamicVerifyMode, setDynamicVerifyMode] = useState<DynamicVerifyMode>(
    normalizeDynamicVerifyMode(project.dynamic_verify_mode, project.dynamic_verify_enabled),
  )
  const [verifier, setVerifier] = useState(Boolean(project.verifier_enabled))
  const [attackChain, setAttackChain] = useState(Boolean(project.attack_chain_enabled))
  const [heuristicEnabled, setHeuristicEnabled] = useState(project.heuristic_enabled !== false)
  const [heuristicLite, setHeuristicLite] = useState(project.heuristic_lite === true)
  const [fastEnabled, setFastEnabled] = useState(project.fast_enabled === true)
  const [bypassEnabled, setBypassEnabled] = useState(project.bypass_enabled === true)
  const [llmModel, setLlmModel] = useState(project.llm_model || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setPrompt(project.manual_lab_prompt || '')
    setDynamicVerifyMode(normalizeDynamicVerifyMode(project.dynamic_verify_mode, project.dynamic_verify_enabled))
    setVerifier(Boolean(project.verifier_enabled))
    setAttackChain(Boolean(project.attack_chain_enabled))
    setHeuristicEnabled(project.heuristic_enabled !== false)
    setHeuristicLite(project.heuristic_lite === true)
    setFastEnabled(project.fast_enabled === true)
    setBypassEnabled(project.bypass_enabled === true)
    setLlmModel(project.llm_model || '')
    setError('')
  }, [
    open,
    project.manual_lab_prompt,
    project.dynamic_verify_mode,
    project.dynamic_verify_enabled,
    project.verifier_enabled,
    project.heuristic_enabled,
    project.heuristic_lite,
    project.fast_enabled,
    project.bypass_enabled,
    project.llm_model,
  ])

  const close = () => {
    if (saving) return
    setOpen(false)
  }

  async function save() {
    setSaving(true)
    setError('')
    try {
      const text = dynamicVerifyMode === 'lab' ? prompt.trim() : ''
      const canEditPaths = project.status === 'paused' || project.status === 'completed'
      const next = await api.updateProject(project.id, {
        manual_lab: Boolean(text),
        manual_lab_prompt: text,
        verifier_enabled: verifier,
        attack_chain_enabled: attackChain,
        dynamic_verify_enabled: dynamicVerifyMode !== 'off',
        dynamic_verify_mode: dynamicVerifyMode,
        llm_model: llmModel.trim(),
        ...(canEditPaths
          ? { heuristic_enabled: heuristicEnabled, heuristic_lite: heuristicLite, fast_enabled: fastEnabled, bypass_enabled: bypassEnabled }
          : {}),
      })
      onSaved(next)
      setOpen(false)
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <Button variant="outline" onClick={() => setOpen(true)}>
        项目配置
      </Button>
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close()
          else setOpen(true)
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-lg" showCloseButton={!saving}>
          <DialogHeader>
            <DialogTitle>项目配置</DialogTitle>
            <DialogDescription>
              审计运行中也可修改模型、验证方式与互联网验证。挖掘路径仅在项目暂停或完成后可改；人工靶场说明仅靶场动态下生效。模型对下一轮 Agent 生效。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <ProjectModelSelect value={llmModel} onValueChange={setLlmModel} />
            <MiningPathSelect
              heuristicEnabled={heuristicEnabled}
              heuristicLite={heuristicLite}
              fastEnabled={fastEnabled}
              bypassEnabled={bypassEnabled}
              disabled={project.status !== 'paused' && project.status !== 'completed'}
              onChange={({ heuristicEnabled: nextH, heuristicLite: nextL, fastEnabled: nextF, bypassEnabled: nextB }) => {
                setHeuristicEnabled(nextH)
                setHeuristicLite(nextL)
                setFastEnabled(nextF)
                setBypassEnabled(nextB)
              }}
            />
            <DynamicVerifyToggle mode={dynamicVerifyMode} onModeChange={setDynamicVerifyMode} />
            {dynamicVerifyMode === 'lab' ? (
              <div className="space-y-2">
                <Label htmlFor="manual-lab-prompt" className="font-medium">
                  人工靶场描述
                </Label>
                <p className="text-xs leading-relaxed text-muted-foreground">{MANUAL_LAB_HINT}</p>
                <Textarea
                  id="manual-lab-prompt"
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder={MANUAL_LAB_PLACEHOLDER}
                  rows={5}
                />
              </div>
            ) : null}
            <VerifierToggle enabled={verifier} onEnabledChange={setVerifier} />
            <AttackChainToggle enabled={attackChain} onEnabledChange={setAttackChain} />
            {error ? <p className="text-sm text-red-300">{error}</p> : null}
          </div>
          <DialogFooter>
            <Button variant="outline" disabled={saving} onClick={close}>
              取消
            </Button>
            <Button disabled={saving} onClick={() => void save()}>
              {saving ? '保存中…' : '保存'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
