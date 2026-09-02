import { useState } from 'react'
import { PauseIcon, PlayIcon } from 'lucide-react'
import { api, formatApiError, type Project } from '../api'
import { applyProjectRunToListCaches } from '../lib/listCache'
import { projectRunBucket, tokenBudgetReached } from '../lib/utils'
import { Button } from '@/components/ui/button'

function optimisticPause(project: Project): Project {
  return { ...project, status: 'paused', project_paused: true }
}

function optimisticResume(project: Project): Project {
  const running = project.recon_done
  return {
    ...project,
    status: running ? 'auditing' : 'recon',
    phase: running
      ? project.phase === 'pending' || project.phase === 'recon'
        ? 'worker'
        : project.phase
      : 'recon',
    project_paused: false,
  }
}

function applyFresh(project: Project) {
  if (!project.notModified && !project.unchanged) applyProjectRunToListCaches(project)
}

export function ProjectRunButtons({ project, size = 'sm' }: { project: Project; size?: 'default' | 'sm' }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const bucket = projectRunBucket(project.status, project.project_paused)
  const budgetBlocked = tokenBudgetReached(project)
  const canPause = !busy && bucket === 'running'
  const canStart = !busy && bucket !== 'running' && !budgetBlocked

  const pauseTitle =
    bucket === 'completed'
      ? '已完成项目不可暂停'
      : bucket === 'paused'
        ? '项目已暂停'
        : bucket === 'stopped'
          ? '已停止项目无需暂停'
          : undefined
  const startTitle = budgetBlocked
    ? '已达到 Token 上限，请在项目配置中提高上限后再启动'
    : bucket === 'running'
      ? '项目已在运行'
      : undefined

  function runAction(kind: 'pause' | 'resume') {
    if (busy) return
    const prev = project
    const next = kind === 'pause' ? optimisticPause(project) : optimisticResume(project)
    setError('')
    applyProjectRunToListCaches(next)
    setBusy(true)
    void (kind === 'pause' ? api.pause(project.id) : api.resume(project.id))
      .then(() => api.getProject(project.id))
      .then(applyFresh)
      .catch((e) => {
        applyProjectRunToListCaches(prev)
        setError(formatApiError(e))
      })
      .finally(() => setBusy(false))
  }

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size={size}
        disabled={!canPause}
        title={pauseTitle}
        aria-label="暂停项目"
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          if (!canPause) return
          runAction('pause')
        }}
      >
        <PauseIcon />
        暂停
      </Button>
      <Button
        type="button"
        variant="outline"
        size={size}
        disabled={!canStart}
        title={startTitle}
        aria-label="启动项目"
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          if (!canStart) return
          runAction('resume')
        }}
      >
        <PlayIcon />
        启动
      </Button>
      {error ? (
        <span className="max-w-40 truncate text-xs text-red-300" title={error}>
          {error}
        </span>
      ) : null}
    </>
  )
}
