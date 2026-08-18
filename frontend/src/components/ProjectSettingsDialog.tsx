import { useEffect, useState } from 'react'
import { api, type Project } from '../api'
import { MANUAL_LAB_HINT, MANUAL_LAB_PLACEHOLDER } from './ManualLabFields'
import { VerifierToggle } from './VerifierToggle'
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
  const [verifier, setVerifier] = useState(Boolean(project.verifier_enabled))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setPrompt(project.manual_lab_prompt || '')
    setVerifier(Boolean(project.verifier_enabled))
    setError('')
  }, [open, project.manual_lab_prompt, project.verifier_enabled])

  const close = () => {
    if (saving) return
    setOpen(false)
  }

  async function save() {
    setSaving(true)
    setError('')
    try {
      const text = prompt.trim()
      const next = await api.updateProject(project.id, {
        manual_lab: Boolean(text),
        manual_lab_prompt: text,
        verifier_enabled: verifier,
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
        <DialogContent className="sm:max-w-lg" showCloseButton={!saving}>
          <DialogHeader>
            <DialogTitle>项目配置</DialogTitle>
            <DialogDescription>
              审计运行中也可修改。人工靶场说明保存后对下一轮审核生效；互联网验证立即按新开关排队。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
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
            <VerifierToggle enabled={verifier} onEnabledChange={setVerifier} />
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
