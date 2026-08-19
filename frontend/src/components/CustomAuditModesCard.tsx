import { useEffect, useState } from 'react'
import { api, type BuiltinAuditMode, type CustomAuditMode } from '../api'
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

const EMPTY_TEMPLATE =
  '## 当前挖掘模式：自定义模式（覆盖上文冲突条款）\n\n' +
  '本项目为**自定义模式**。若与上文基座提示冲突，**以本节为准**。\n' +
  '本节仅约束漏洞收录与确认标准，不改变工具权限。\n\n' +
  '### 接收类型\n（在此填写要收录的漏洞类型与判定标准）\n\n' +
  '### 明确丢弃\n（在此填写不要提交/确认的类型）\n'

export function CustomAuditModesCard() {
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
      setMsg(String(e))
    })
  }, [])

  function openCreate(from?: BuiltinAuditMode | null) {
    setEditingId(null)
    setName(from ? `基于${from.label}` : '')
    setBody(from ? from.body : EMPTY_TEMPLATE)
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
      setMsg(editingId == null ? '已创建自定义审计模式' : '已保存自定义审计模式')
    } catch (e) {
      setOk(false)
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function remove(row: CustomAuditMode) {
    if (!window.confirm(`删除自定义模式「${row.name}」？仍被项目引用时会失败。`)) return
    setBusy(true)
    setMsg('')
    setOk(null)
    try {
      await api.deleteCustomAuditMode(row.id)
      await refresh()
      setOk(true)
      setMsg(`已删除「${row.name}」`)
    } catch (e) {
      setOk(false)
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardContent className="space-y-4 p-4">
          <div className="space-y-1.5">
            <Label>挖掘模式提示词</Label>
            <div className="text-xs text-slate-500">
              内置赏金/全量提示词只读，可复制为自定义。自定义模式在创建项目时选用；写入项目的是快照，之后改库不影响已绑定项目。
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium text-slate-200">内置模式（只读）</div>
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
                      查看
                    </Button>
                    <Button type="button" variant="secondary" size="sm" onClick={() => openCreate(b)}>
                      复制为自定义
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-medium text-slate-200">自定义模式</div>
              <Button type="button" size="sm" onClick={() => openCreate(null)}>
                新建
              </Button>
            </div>
            {rows.length === 0 ? (
              <div className="text-xs text-muted-foreground">暂无自定义模式。可从赏金/全量复制，或新建空白模板。</div>
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
                        查看
                      </Button>
                      <Button type="button" variant="secondary" size="sm" onClick={() => openEdit(row)}>
                        编辑
                      </Button>
                      <Button type="button" variant="destructive" size="sm" disabled={busy} onClick={() => void remove(row)}>
                        删除
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {msg ? (
            <div className="flex items-start gap-2 text-sm">
              {ok != null ? <Badge variant={ok ? 'success' : 'destructive'}>{ok ? '成功' : '失败'}</Badge> : null}
              <span className={ok === false ? 'text-red-300' : 'text-slate-300'}>{msg}</span>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>{editingId == null ? '新建自定义审计模式' : '编辑自定义审计模式'}</DialogTitle>
            <DialogDescription>名称与正文均不能为空。项目选用后会快照正文，改库不影响已创建项目。</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 space-y-3 overflow-auto px-5 py-4">
            <div className="space-y-1.5">
              <Label htmlFor="custom-mode-name">名称</Label>
              <Input
                id="custom-mode-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如：只挖注入与文件"
                maxLength={128}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="custom-mode-body">提示词正文</Label>
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
              取消
            </Button>
            <Button type="button" onClick={() => void saveEditor()} disabled={busy || !name.trim() || !body.trim()}>
              {busy ? '保存中…' : '保存'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={viewOpen} onOpenChange={setViewOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>{viewTitle}</DialogTitle>
            <DialogDescription>只读预览</DialogDescription>
          </DialogHeader>
          <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-5 py-4 font-mono text-xs leading-relaxed text-slate-300">
            {viewBody}
          </pre>
        </DialogContent>
      </Dialog>
    </>
  )
}
