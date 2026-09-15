import { useEffect, useState } from 'react'
import { api, formatApiError, type BuiltinAuditMode, type CustomAuditMode } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useI18n } from '@/i18n'

export function CustomAuditModesCard() {
  const { t } = useI18n()
  const [builtin, setBuiltin] = useState<BuiltinAuditMode[]>([])
  const [rows, setRows] = useState<CustomAuditMode[]>([])
  const [msg, setMsg] = useState('')
  const [ok, setOk] = useState<boolean | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [name, setName] = useState('')
  const [body, setBody] = useState('')
  const [viewOpen, setViewOpen] = useState(false)
  const [viewTitle, setViewTitle] = useState('')
  const [viewBody, setViewBody] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    const [b, c] = await Promise.all([api.listBuiltinAuditModes(), api.listCustomAuditModes()])
    setBuiltin(b)
    setRows(c)
  }

  useEffect(() => {
    refresh().catch((e) => {
      setOk(false)
      setMsg(formatApiError(e))
    })
  }, [])

  function openCreate(from?: BuiltinAuditMode | null) {
    setEditingId(null)
    setName(from ? t('settings.custom.basedOn', { label: from.label }) : '')
    setBody(from ? from.body : t('settings.custom.template'))
    setEditorOpen(true)
  }

  function openEdit(row: CustomAuditMode) {
    setEditingId(row.id)
    setName(row.name)
    setBody(row.body)
    setEditorOpen(true)
  }

  function openView(title: string, text: string) {
    setViewTitle(title)
    setViewBody(text)
    setViewOpen(true)
  }

  async function saveEditor() {
    setBusy(true)
    setMsg('')
    setOk(null)
    try {
      if (editingId == null) {
        await api.createCustomAuditMode({ name: name.trim(), body: body.trim() })
      } else {
        await api.updateCustomAuditMode(editingId, { name: name.trim(), body: body.trim() })
      }
      setEditorOpen(false)
      await refresh()
      setOk(true)
      setMsg(editingId == null ? t('settings.custom.created') : t('settings.custom.updated'))
    } catch (e) {
      setOk(false)
      setMsg(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  async function remove(row: CustomAuditMode) {
    if (!window.confirm(t('settings.custom.deleteConfirm', { name: row.name }))) return
    setBusy(true)
    setMsg('')
    setOk(null)
    try {
      await api.deleteCustomAuditMode(row.id)
      await refresh()
      setOk(true)
      setMsg(t('settings.custom.deleted', { name: row.name }))
    } catch (e) {
      setOk(false)
      setMsg(formatApiError(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardContent className="space-y-4 p-4">
          <div className="space-y-1.5">
            <Label>{t('settings.custom.label')}</Label>
            <div className="text-xs text-slate-500">{t('settings.custom.hint')}</div>
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium text-slate-200">{t('settings.custom.builtin')}</div>
            <div className="space-y-2">
              {builtin.map((b) => (
                <div
                  key={b.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/60 px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="font-medium">{b.label}</div>
                    <div className="text-xs text-muted-foreground">{b.id}</div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button type="button" variant="outline" size="sm" onClick={() => openView(b.label, b.body)}>
                      {t('settings.custom.view')}
                    </Button>
                    <Button type="button" variant="secondary" size="sm" onClick={() => openCreate(b)}>
                      {t('settings.custom.copy')}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-medium text-slate-200">{t('settings.custom.list')}</div>
              <Button type="button" size="sm" onClick={() => openCreate(null)}>
                {t('common.create')}
              </Button>
            </div>
            {rows.length === 0 ? (
              <div className="text-xs text-muted-foreground">{t('settings.custom.empty')}</div>
            ) : (
              <div className="space-y-2">
                {rows.map((row) => (
                  <div
                    key={row.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/60 px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="font-medium">{row.name}</div>
                      <div className="truncate text-xs text-muted-foreground">
                        {row.body.replace(/\s+/g, ' ').slice(0, 80)}
                        {row.body.length > 80 ? '…' : ''}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Button type="button" variant="outline" size="sm" onClick={() => openView(row.name, row.body)}>
                        {t('settings.custom.view')}
                      </Button>
                      <Button type="button" variant="secondary" size="sm" onClick={() => openEdit(row)}>
                        {t('common.edit')}
                      </Button>
                      <Button type="button" variant="destructive" size="sm" disabled={busy} onClick={() => void remove(row)}>
                        {t('common.delete')}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {msg ? (
            <div className="flex items-start gap-2 text-sm">
              {ok != null ? (
                <Badge variant={ok ? 'success' : 'destructive'}>{ok ? t('common.success') : t('common.fail')}</Badge>
              ) : null}
              <span className={ok === false ? 'text-red-300' : 'text-slate-300'}>{msg}</span>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>
              {editingId == null ? t('settings.custom.createTitle') : t('settings.custom.editTitle')}
            </DialogTitle>
            <DialogDescription>{t('settings.custom.editorHint')}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-3 overflow-auto px-5 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="custom-mode-name">{t('settings.custom.name')}</Label>
              <Input
                id="custom-mode-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t('settings.custom.namePlaceholder')}
                maxLength={128}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="custom-mode-body">{t('settings.custom.body')}</Label>
              <Textarea
                id="custom-mode-body"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="min-h-72 font-mono text-xs"
                maxLength={16000}
              />
              <div className="text-xs text-muted-foreground">{body.length} / 16000</div>
            </div>
          </div>
          <DialogFooter className="shrink-0 border-t border-border px-5 py-3">
            <Button type="button" variant="outline" onClick={() => setEditorOpen(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="button" onClick={() => void saveEditor()} disabled={busy || !name.trim() || !body.trim()}>
              {busy ? t('settings.token.saving') : t('common.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={viewOpen} onOpenChange={setViewOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>{viewTitle}</DialogTitle>
            <DialogDescription>{t('settings.custom.readonlyPreview')}</DialogDescription>
          </DialogHeader>
          <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-5 py-4 font-mono text-xs leading-relaxed text-slate-300">
            {viewBody}
          </pre>
        </DialogContent>
      </Dialog>
    </>
  )
}
