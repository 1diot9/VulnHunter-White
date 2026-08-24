import { useEffect, useState } from 'react'
import { api, type Project, type ProjectLab } from '../api'
import { Button } from '@/components/ui/button'
import { startVisibilityPoll } from '../lib/visibilityPoll'

type PortFieldKey = 'host' | 'jdwp' | 'inspect' | 'debugpy'

function PortField({
  label,
  display,
  editing,
  portInput,
  busy,
  onEdit,
  onSave,
  onCancel,
  onPortInputChange,
  showEdit,
}: {
  label: string
  display: string | null
  editing: boolean
  portInput: string
  busy: boolean
  onEdit: () => void
  onSave: () => void
  onCancel: () => void
  onPortInputChange: (v: string) => void
  showEdit: boolean
}) {
  return (
    <span className="flex flex-wrap items-center gap-1">
      <span className="text-slate-400">{label}：</span>
      {editing ? (
        <>
          <span className="text-xs text-slate-500">127.0.0.1:</span>
          <input
            type="number"
            className="w-20 rounded border border-slate-600 bg-slate-900 px-1 py-0.5 text-sm"
            value={portInput}
            min={1}
            max={65535}
            onChange={(e) => onPortInputChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') onSave()
              if (e.key === 'Escape') onCancel()
            }}
            autoFocus
          />
          <button
            type="button"
            className="text-xs text-sky-400 hover:underline"
            onClick={onSave}
            disabled={busy}
          >
            保存
          </button>
          <button
            type="button"
            className="text-xs text-slate-400 hover:underline"
            onClick={onCancel}
          >
            取消
          </button>
        </>
      ) : (
        <>
          <span className="font-mono text-slate-200">{display || '—'}</span>
          {showEdit && (
            <button
              type="button"
              className="ml-1 text-xs text-slate-400 hover:text-sky-400 hover:underline"
              onClick={onEdit}
              title={`修改 ${label} 端口`}
            >
              [改]
            </button>
          )}
        </>
      )}
    </span>
  )
}

type LabControlPanelProps = {
  project: Project
}

export function LabControlPanel({ project }: LabControlPanelProps) {
  const [lab, setLab] = useState<ProjectLab | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [editingField, setEditingField] = useState<PortFieldKey | null>(null)
  const [portInput, setPortInput] = useState('')

  const refresh = async () => {
    try {
      const next = await api.getLab(project.id)
      setLab(next)
      setError(next.error || '')
    } catch (e) {
      setError(String(e))
    }
  }

  useEffect(() => {
    void refresh()
    return startVisibilityPoll(() => {
      void refresh()
    }, 5000)
  }, [project.id])

  async function runAction(action: 'start' | 'stop') {
    if (busy) return
    setBusy(true)
    setError('')
    setNote('')
    try {
      const next = action === 'start' ? await api.startLab(project.id) : await api.stopLab(project.id)
      setLab(next)
      if (next.port_changes?.length) {
        setNote(`已自动换端口：${next.port_changes.join('；')}`)
      }
      setError(next.error || '')
    } catch (e) {
      setError(String(e))
      void refresh()
    } finally {
      setBusy(false)
    }
  }

  async function savePort() {
    if (!editingField || busy) return
    const port = Number(portInput)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setError('端口须为 1–65535 的整数')
      return
    }
    setBusy(true)
    setError('')
    try {
      const payload =
        editingField === 'jdwp'
          ? { jdwp_host_port: port }
          : editingField === 'inspect'
            ? { inspect_host_port: port }
            : editingField === 'debugpy'
              ? { debugpy_host_port: port }
              : { host_port: port }
      const next = await api.patchLab(project.id, payload)
      setLab(next)
      setEditingField(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const hasEnv = Boolean(lab?.has_env)
  const showEdit = hasEnv && !busy

  return (
    <div className="rounded-lg border border-slate-700/80 bg-slate-900/40 px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium text-slate-200">Docker 靶场</div>
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !hasEnv || lab?.status === 'running'}
            title={
              !hasEnv
                ? '尚无 env 产物，请先在阶段日志「环境搭建」完成搭建'
                : lab?.status === 'running'
                  ? '靶场已在运行'
                  : '一键启动 Docker 靶场（端口冲突时自动换端口）'
            }
            onClick={() => void runAction('start')}
          >
            启动靶场
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !lab?.can_stop}
            onClick={() => void runAction('stop')}
          >
            停止
          </Button>
        </div>
      </div>

      {!hasEnv ? (
        <p className="text-sm text-slate-400">
          尚无靶场产物。请先在阶段日志的「环境搭建」中完成搭建，再使用一键启动。
        </p>
      ) : (
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          <span>
            状态：<span className="font-medium text-slate-100">{lab?.status || 'absent'}</span>
          </span>
          <PortField
            label="地址"
            display={lab?.target_url || null}
            editing={editingField === 'host'}
            portInput={portInput}
            busy={busy}
            onEdit={() => {
              setPortInput(String(lab?.host_port ?? ''))
              setEditingField('host')
            }}
            onSave={() => void savePort()}
            onCancel={() => setEditingField(null)}
            onPortInputChange={setPortInput}
            showEdit={showEdit}
          />
          {(lab?.jdwp_host_port != null || editingField === 'jdwp') && (
            <PortField
              label="JDWP"
              display={lab?.jdwp_host_port ? `127.0.0.1:${lab.jdwp_host_port}` : null}
              editing={editingField === 'jdwp'}
              portInput={portInput}
              busy={busy}
              onEdit={() => {
                setPortInput(String(lab?.jdwp_host_port ?? ''))
                setEditingField('jdwp')
              }}
              onSave={() => void savePort()}
              onCancel={() => setEditingField(null)}
              onPortInputChange={setPortInput}
              showEdit={showEdit}
            />
          )}
          {(lab?.inspect_host_port != null || editingField === 'inspect') && (
            <PortField
              label="Inspect"
              display={lab?.inspect_host_port ? `127.0.0.1:${lab.inspect_host_port}` : null}
              editing={editingField === 'inspect'}
              portInput={portInput}
              busy={busy}
              onEdit={() => {
                setPortInput(String(lab?.inspect_host_port ?? ''))
                setEditingField('inspect')
              }}
              onSave={() => void savePort()}
              onCancel={() => setEditingField(null)}
              onPortInputChange={setPortInput}
              showEdit={showEdit}
            />
          )}
          {(lab?.debugpy_host_port != null || editingField === 'debugpy') && (
            <PortField
              label="debugpy"
              display={lab?.debugpy_host_port ? `127.0.0.1:${lab.debugpy_host_port}` : null}
              editing={editingField === 'debugpy'}
              portInput={portInput}
              busy={busy}
              onEdit={() => {
                setPortInput(String(lab?.debugpy_host_port ?? ''))
                setEditingField('debugpy')
              }}
              onSave={() => void savePort()}
              onCancel={() => setEditingField(null)}
              onPortInputChange={setPortInput}
              showEdit={showEdit}
            />
          )}
          {lab?.image && <span className="text-slate-500">{lab.image}</span>}
        </div>
      )}

      {lab?.port_conflicts && lab.port_conflicts.length > 0 && lab.status !== 'running' && (
        <p className="mt-2 text-xs text-amber-400/90">
          端口占用：{lab.port_conflicts.join(', ')}（启动时将自动更换，也可手动改端口）
        </p>
      )}
      {note && <p className="mt-2 text-xs text-emerald-400/90">{note}</p>}
      {error && <p className="mt-2 text-xs text-rose-400/90">{error}</p>}
    </div>
  )
}
