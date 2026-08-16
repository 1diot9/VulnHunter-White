import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

const PHASES = [
  { id: 'recon', label: '侦察' },
  { id: 'worker', label: '挖掘' },
  { id: 'reviewer', label: '审核' },
  { id: 'done', label: '完成' },
] as const

type Tone = 'neutral' | 'success' | 'info'

function badgeVariant(tone: Tone): 'outline' | 'success' | 'info' {
  if (tone === 'success') return 'success'
  if (tone === 'info') return 'info'
  return 'outline'
}

export type ReconSubphaseView = {
  id: string
  label: string
  done: boolean
}

type FlowState = {
  phase: string
  status: string
  reconDone: boolean
  filesAudited?: number
  filesSkipped?: number
  filesTotal?: number
  vulnPending?: number
  reconSubphases?: ReconSubphaseView[]
}

function workerFinished(s: FlowState): boolean {
  const total = s.filesTotal ?? 0
  if (!s.reconDone || total <= 0) return false
  return (s.filesAudited ?? 0) + (s.filesSkipped ?? 0) >= total
}

function phaseTone(id: string, s: FlowState): Tone {
  const completed = s.status === 'completed' || s.phase === 'done'
  if (completed) return 'success'

  const workerDone = workerFinished(s)
  if (id === 'recon') {
    if (s.reconDone) return 'success'
    if (s.phase === 'recon' || s.status === 'recon' || s.status === 'ingesting') return 'info'
    return 'neutral'
  }
  if (id === 'worker') {
    if (workerDone) return 'success'
    if (s.phase === 'worker' || s.phase === 'fix' || s.status === 'auditing' || (s.reconDone && !workerDone)) {
      return 'info'
    }
    return 'neutral'
  }
  if (id === 'reviewer') {
    if (s.phase === 'reviewer' || s.status === 'reviewing' || (s.vulnPending ?? 0) > 0) return 'info'
    return 'neutral'
  }
  return 'neutral'
}

function subphaseTone(item: ReconSubphaseView, all: ReconSubphaseView[], s: FlowState): Tone {
  if (item.done || s.reconDone) return 'success'
  if (s.status === 'completed' || s.phase === 'done') return 'neutral'
  const firstOpen = all.find((x) => !x.done)
  if (firstOpen?.id === item.id) return 'info'
  return 'neutral'
}

export default function PhaseFlow({
  phase,
  status,
  reconDone,
  filesAudited,
  filesSkipped,
  filesTotal,
  vulnPending,
  reconSubphases,
  onSelect,
}: FlowState & { onSelect?: (id: string) => void }) {
  const state: FlowState = {
    phase,
    status,
    reconDone,
    filesAudited,
    filesSkipped,
    filesTotal,
    vulnPending,
    reconSubphases,
  }
  const subs = reconSubphases ?? []
  return (
    <div className="flex flex-wrap items-center gap-2">
      {PHASES.map((p, i) => (
        <div key={p.id} className="flex items-center gap-2">
          <div className="flex flex-col items-start gap-1">
            <Button
              type="button"
              variant="ghost"
              size="xs"
              onClick={() => onSelect?.(p.id)}
              className="h-auto rounded-md p-0"
            >
              <Badge variant={badgeVariant(phaseTone(p.id, state))}>{p.label}</Badge>
            </Button>
            {p.id === 'recon' && subs.length > 0 ? (
              <div className="flex flex-wrap items-center gap-1">
                {subs.map((item, si) => (
                  <div key={item.id} className="flex items-center gap-1">
                    {si > 0 ? <span className="text-[10px] text-slate-600">→</span> : null}
                    <Badge variant={badgeVariant(subphaseTone(item, subs, state))}>
                      {item.label}
                      {item.done ? ' ✓' : ''}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
          {i < PHASES.length - 1 ? <span className="text-slate-600">→</span> : null}
        </div>
      ))}
    </div>
  )
}
