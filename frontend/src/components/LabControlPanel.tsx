import { useEffect, useState } from 'react'
import { api, formatApiError, type Project, type ProjectLab } from '../api'
import { Button } from '@/components/ui/button'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { useI18n } from '@/i18n'

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
  const { t } = useI18n()
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
            {t('flow.lab.save')}
          </button>
          <button
            type="button"
            className="text-xs text-slate-400 hover:underline"
            onClick={onCancel}
          >
            {t('common.cancel')}
          </button>
        </>
      ) : (
        <>
          <span className="font-mono text-slate-200">{display || t('common.dash')}</span>
          {showEdit && (
            <button
              type="button"
              className="ml-1 text-xs text-slate-400 hover:text-sky-400 hover:underline"
              onClick={onEdit}
              title={t('flow.lab.portTitle', { label })}
            >
              {t('flow.lab.edit')}
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
  const { t } = useI18n()
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
      setError(formatApiError(e, t('flow.lab.timeout')))
    }
  }

  useEffect(() => {
    let stop: (() => void) | undefined
    const timer = window.setTimeout(() => {
      stop = startVisibilityPoll(() => {
        void refresh()
      }, 8000)
    }, 400)
    return () => {
      window.clearTimeout(timer)
      stop?.()
    }
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
        setNote(t('flow.lab.portAuto', { ports: next.port_changes.join('；') }))
      }
      setError(next.error || '')
    } catch (e) {
      setError(formatApiError(e, t('flow.lab.timeout')))
      void refresh()
    } finally {
      setBusy(false)
    }
  }

  async function savePort() {
    if (!editingField || busy) return
    const port = Number(portInput)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setError(t('flow.lab.portRange'))
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
      setError(formatApiError(e, t('flow.lab.timeout')))
    } finally {
      setBusy(false)
    }
  }

  const hasEnv = Boolean(lab?.has_env)
  const showEdit = hasEnv && !busy

  return (
    <div className="rounded-lg border border-slate-700/80 bg-slate-900/40 px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-medium text-slate-200">{t('flow.lab.title')}</div>
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !hasEnv || lab?.status === 'running'}
            title={
              !hasEnv
                ? t('flow.lab.needEnv')
                : lab?.status === 'running'
                  ? t('flow.lab.running')
                  : t('flow.lab.oneClick')
            }
            onClick={() => void runAction('start')}
          >
            {t('flow.lab.start')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={busy || !lab?.can_stop}
            onClick={() => void runAction('stop')}
          >
            {t('flow.lab.stop')}
          </Button>
        </div>
      </div>

      {!hasEnv ? (
        <p className="text-sm text-slate-400">{t('flow.lab.none')}</p>
      ) : (
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          <span>
            {t('flow.lab.status')}
            <span className="font-medium text-slate-100">{lab?.status || 'absent'}</span>
          </span>
          <PortField
            label={t('flow.lab.url')}
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
          {t('flow.lab.portBusy', { ports: lab.port_conflicts.join(', ') })}
        </p>
      )}
      {note && <p className="mt-2 text-xs text-emerald-400/90">{note}</p>}
      {error && <p className="mt-2 text-xs text-rose-400/90">{error}</p>}
    </div>
  )
}
