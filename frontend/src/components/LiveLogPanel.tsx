import { useEffect, useLayoutEffect, useMemo, useRef, useState, type MutableRefObject, type WheelEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { LogEvent } from '../api'
import { useI18n } from '@/i18n'
import { t as translate } from '@/i18n/t'

type Props = {
  events: LogEvent[]
  minHeight?: number
  autoScroll?: boolean
  phaseFilter?: string
  hasOlder?: boolean
  loadingOlder?: boolean
  revealLimit?: number
  onLoadOlder?: () => void
  /** 仅当视口仍钉在当前窗口顶部时为 true；离开顶部后进行中的「更早」请求应丢弃。 */
  atTopRef?: MutableRefObject<boolean>
  session?: number
  sessionCount?: number
  onSessionChange?: (session: number | null) => void
  /** 当前小阶段是否仍有 Agent 在跑；最新一轮仅在此时显示「运行中」。 */
  phaseRunning?: boolean | null
}

function phaseLabelMap(): Record<string, string> {
  const t = translate
  return {
    recon: t('flow.log.reconMap'),
    'recon-map': t('flow.log.reconMap'),
    'recon-source-ext': t('flow.log.reconExt'),
    recon_source_ext: t('flow.log.reconExt'),
    'recon-old-vuln': t('flow.log.reconOld'),
    recon_old_vuln: t('flow.log.reconOld'),
    'recon-old-vuln-ghsa': t('flow.log.reconOldFill'),
    recon_old_vuln_ghsa: t('flow.log.reconOldFill'),
    'recon-mark': t('flow.log.reconMark'),
    recon_mark: t('flow.log.reconMark'),
    'code-intel': t('flow.phase.codeIntel'),
    code_intel: t('flow.phase.codeIntel'),
    worker: t('flow.phase.worker'),
    'fast-worker': t('mining.fast'),
    fast_worker: t('mining.fast'),
    'bypass-worker': t('mining.bypass'),
    bypass_worker: t('mining.bypass'),
    'unconstrained-worker': t('mining.unconstrained'),
    unconstrained_worker: t('mining.unconstrained'),
    'sink-triage': t('flow.log.sinkTriage'),
    sink_triage: t('flow.log.sinkTriage'),
    reviewer: t('flow.phase.reviewer'),
    'reviewer-lab': t('flow.log.reviewerLab'),
    reviewer_lab: t('flow.log.reviewerLab'),
    'reviewer-review': t('flow.phase.reviewer'),
    verifier: t('flow.phase.verifier'),
    attack_chain: t('flow.phase.attackChain'),
    'attack-chain': t('flow.phase.attackChain'),
    vuln_dedup: t('flow.log.dedup'),
    'vuln-dedup': t('flow.log.dedup'),
    fix: t('flow.log.fix'),
    mine: t('flow.phase.worker'),
  }
}

export function eventMatchesPhase(ev: LogEvent, phaseFilter?: string): boolean {
  if (!phaseFilter) return true
  const p = ev.phase || ev.role || ''
  if (phaseFilter === 'worker') {
    return (
      p === 'worker' ||
      p === 'fix' ||
      p === 'fast-worker' ||
      p === 'fast_worker' ||
      p === 'sink-triage' ||
      p === 'sink_triage' ||
      p === 'bypass-worker' ||
      p === 'bypass_worker' ||
      p === 'unconstrained-worker' ||
      p === 'unconstrained_worker'
    )
  }
  if (phaseFilter === 'mine') {
    return p === 'worker'
  }
  if (phaseFilter === 'fast' || phaseFilter === 'fast-worker' || phaseFilter === 'fast_worker') {
    return p === 'fast-worker' || p === 'fast_worker' || p === 'sink-triage' || p === 'sink_triage'
  }
  if (phaseFilter === 'bypass' || phaseFilter === 'bypass-worker' || phaseFilter === 'bypass_worker') {
    return p === 'bypass-worker' || p === 'bypass_worker'
  }
  if (
    phaseFilter === 'unconstrained' ||
    phaseFilter === 'unconstrained-worker' ||
    phaseFilter === 'unconstrained_worker'
  ) {
    return p === 'unconstrained-worker' || p === 'unconstrained_worker'
  }
  if (phaseFilter === 'sink-triage' || phaseFilter === 'sink_triage') {
    return p === 'sink-triage' || p === 'sink_triage'
  }
  if (phaseFilter === 'fix') return p === 'fix'
  if (phaseFilter === 'recon') {
    return (
      p === 'recon' ||
      p === 'recon-mark' ||
      p === 'recon_mark' ||
      p === 'recon-source-ext' ||
      p === 'recon_source_ext' ||
      p === 'recon-old-vuln' ||
      p === 'recon_old_vuln' ||
      p === 'recon-old-vuln-ghsa' ||
      p === 'recon_old_vuln_ghsa'
    )
  }
  if (phaseFilter === 'recon-map') return p === 'recon'
  if (phaseFilter === 'recon-source-ext') return p === 'recon-source-ext' || p === 'recon_source_ext'
  if (phaseFilter === 'recon-old-vuln') {
    return (
      p === 'recon-old-vuln' ||
      p === 'recon_old_vuln' ||
      p === 'recon-old-vuln-ghsa' ||
      p === 'recon_old_vuln_ghsa'
    )
  }
  if (phaseFilter === 'recon-mark') return p === 'recon-mark' || p === 'recon_mark'
  if (phaseFilter === 'code-intel' || phaseFilter === 'code_intel') {
    return p === 'code_intel' || p === 'code-intel'
  }
  if (phaseFilter === 'reviewer') {
    return p === 'reviewer' || p === 'reviewer-lab' || p === 'reviewer_lab'
  }
  if (phaseFilter === 'reviewer-lab') return p === 'reviewer-lab' || p === 'reviewer_lab'
  if (phaseFilter === 'reviewer-review') return p === 'reviewer'
  if (phaseFilter === 'verifier') return p === 'verifier'
  if (phaseFilter === 'attack_chain' || phaseFilter === 'attack-chain') {
    return p === 'attack_chain' || p === 'attack-chain'
  }
  if (phaseFilter === 'vuln_dedup' || phaseFilter === 'vuln-dedup') {
    return p === 'vuln_dedup' || p === 'vuln-dedup'
  }
  return p === phaseFilter
}

/** 控制台窗口只计当前阶段；无阶段 system 不占「最近 100 条」。 */
export function eventVisibleInPhase(ev: LogEvent, phaseFilter?: string): boolean {
  return eventMatchesPhase(ev, phaseFilter)
}

function phaseLabel(ev: LogEvent): string {
  const p = ev.role || ev.phase || ''
  return phaseLabelMap()[p] || p
}

function LogLine({ ev }: { ev: LogEvent }) {
  const [expanded, setExpanded] = useState(false)
  const k = ev.kind
  let body = ''
  let collapsible = false
  let tag = k

  if (k === 'agent' || k === 'reasoning') {
    collapsible = true
    body = ev.text || ''
    if (!body.trim()) return null
  } else if (k === 'cmd') {
    collapsible = true
    tag = ev.tool || 'cmd'
    body =
      '$ ' +
      (ev.command || '') +
      (ev.output ? '\n' + ev.output : '') +
      (ev.exit_code != null ? `\n[exit ${ev.exit_code}]` : '')
  } else if (k === 'tool_exec_error') {
    collapsible = true
    tag = ev.tool || 'tool_exec_error'
    body =
      (ev.command ? `$ ${ev.command}\n` : '') +
      (ev.text || ev.output || translate('flow.log.toolFail')) +
      (ev.traceback ? `\n${ev.traceback}` : '')
  } else if (k === 'tokens') {
    const cached = Number(ev.cached) || 0
    body =
      `tokens: ${ev.total ?? 0} (in ${ev.input ?? 0} / out ${ev.output_tokens ?? ev.output ?? 0}` +
      (cached > 0 ? ` / cache ${cached}` : '') +
      ')'
  } else if (k === 'error') {
    body = ev.text || ''
  } else if (k === 'system') {
    tag = ev.source || 'system'
    body = ev.text || ''
  } else {
    body = ev.text || JSON.stringify(ev)
  }

  const shown =
    expanded ? body : k === 'cmd' || k === 'tool_exec_error' ? `$ ${ev.command || ''}` : body
  const hidden =
    k === 'cmd' || k === 'tool_exec_error'
      ? (ev.output || ev.text ? String(ev.output || ev.text).split('\n').length : 0) +
        (ev.exit_code != null ? 1 : 0)
      : Math.max(0, body.split('\n').length - 1)
  const tagClass =
    'vh-tag ' +
    (k === 'system' && ev.source === 'user'
      ? 'user'
      : k === 'cmd'
        ? 'cmd'
        : k === 'tool_exec_error'
          ? 'error'
          : k)
  const label = ev.phase || ev.role ? phaseLabel(ev) : ''

  return (
    <div className={'vh-log-line' + (collapsible ? ' collapsible' + (expanded ? ' expanded' : '') : '')}>
      {ev.ts ? <span className="vh-log-ts">{ev.ts}</span> : null}
      <span className={tagClass} onClick={collapsible ? () => setExpanded((x) => !x) : undefined}>
        {tag}
      </span>
      {label ? <span className="vh-log-phase">{label}</span> : null}
      <span
        className={
          'vh-log-body' +
          (k === 'cmd' || k === 'tool_exec_error' ? ' cmd-text' : '') +
          (k === 'error' || k === 'tool_exec_error' ? ' error-text' : '')
        }
        onClick={collapsible && !expanded ? () => setExpanded(true) : undefined}
      >
        {shown}
      </span>
      {collapsible ? (
        <>
          {!expanded && hidden > 0 ? <span className="vh-line-hint">{translate('flow.log.hiddenLines', { hidden })}</span> : null}
          <span className="vh-caret" onClick={() => setExpanded((x) => !x)}>
            {expanded ? '▾' : '▸'}
          </span>
        </>
      ) : null}
    </div>
  )
}

function windowSlice(list: LogEvent[], limit: number, following: boolean, headSeq?: number): LogEvent[] {
  if (list.length <= limit) return list
  if (following || headSeq == null) return list.slice(-limit)
  const i = list.findIndex((e) => e.seq === headSeq)
  if (i <= 0) return list.slice(0, limit)
  return list.slice(i, i + limit)
}

export default function LiveLogPanel({
  events,
  minHeight = 360,
  autoScroll = true,
  phaseFilter = 'recon',
  hasOlder = false,
  loadingOlder = false,
  revealLimit = 100,
  onLoadOlder,
  atTopRef,
  session = 1,
  sessionCount = 1,
  onSessionChange,
  phaseRunning = null,
}: Props) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  const atBottomRef = useRef(true)
  const prevFirstSeq = useRef<number | undefined>(undefined)
  const prevLastSeq = useRef<number | undefined>(undefined)
  const prevHeight = useRef(0)
  const savedScrollTop = useRef(0)
  const ignoreScrollRef = useRef(false)
  const lastUserLoadAt = useRef(0)
  const [following, setFollowing] = useState(true)
  const [headSeq, setHeadSeq] = useState<number | undefined>(undefined)
  const [showJump, setShowJump] = useState(false)
  const [draft, setDraft] = useState(String(session))
  const [editing, setEditing] = useState(false)
  const skipBlurCommit = useRef(false)

  const filtered = useMemo(
    () => events.filter((ev) => eventVisibleInPhase(ev, phaseFilter)),
    [events, phaseFilter],
  )
  const visible = useMemo(
    () => windowSlice(filtered, revealLimit, following, headSeq),
    [filtered, revealLimit, following, headSeq],
  )
  const moreHidden = filtered.length > visible.length || hasOlder

  useLayoutEffect(() => {
    prevFirstSeq.current = undefined
    prevLastSeq.current = undefined
    prevHeight.current = 0
    atBottomRef.current = true
    if (atTopRef) atTopRef.current = false
    setFollowing(true)
    setHeadSeq(undefined)
  }, [phaseFilter, session, atTopRef])

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const firstSeq = visible[0]?.seq
    const lastSeq = visible[visible.length - 1]?.seq
    const prepended =
      prevFirstSeq.current != null &&
      firstSeq != null &&
      firstSeq < prevFirstSeq.current &&
      lastSeq === prevLastSeq.current
    ignoreScrollRef.current = true
    if (prepended) {
      const delta = el.scrollHeight - prevHeight.current
      if (following || atBottomRef.current) {
        el.scrollTop = el.scrollHeight
      } else {
        el.scrollTop = savedScrollTop.current + delta
      }
    } else if (autoScroll && (following || atBottomRef.current)) {
      el.scrollTop = el.scrollHeight
    }
    prevFirstSeq.current = firstSeq
    prevLastSeq.current = lastSeq
    prevHeight.current = el.scrollHeight
    const t = window.setTimeout(() => {
      ignoreScrollRef.current = false
    }, 80)
    return () => window.clearTimeout(t)
  }, [visible, autoScroll, following])

  useEffect(() => {
    if (!editing) setDraft(String(session))
  }, [session, editing])

  const requestOlder = () => {
    if (!hasOlder || loadingOlder || following) return
    const now = Date.now()
    if (now - lastUserLoadAt.current < 400) return
    lastUserLoadAt.current = now
    onLoadOlder?.()
  }

  const onWheel = (e: WheelEvent<HTMLDivElement>) => {
    const el = ref.current
    if (!el || ignoreScrollRef.current) return
    if (e.deltaY >= 0) {
      if (atTopRef) atTopRef.current = false
      return
    }
    if (following) return
    if (el.scrollTop > 1) return
    if (el.scrollHeight <= el.clientHeight + 8) return
    if (atTopRef) atTopRef.current = true
    requestOlder()
  }

  const onScroll = () => {
    const el = ref.current
    if (!el || ignoreScrollRef.current) return
    const top = el.scrollTop
    savedScrollTop.current = top
    const atBottom = el.scrollHeight - top - el.clientHeight < 40
    atBottomRef.current = atBottom
    if (atBottom) {
      setFollowing(true)
      setHeadSeq(undefined)
      if (atTopRef) atTopRef.current = false
    } else {
      setFollowing((was) => {
        if (was) setHeadSeq(visible[0]?.seq)
        return false
      })
      if (atTopRef) atTopRef.current = top <= 1
    }
    setShowJump(!atBottom)
  }

  const jumpToBottom = () => {
    const el = ref.current
    if (!el) return
    el.scrollTop = el.scrollHeight
    atBottomRef.current = true
    setFollowing(true)
    setHeadSeq(undefined)
    if (atTopRef) atTopRef.current = false
    setShowJump(false)
  }

  const isLatest = session >= sessionCount
  const isLive = isLatest && phaseRunning !== false
  const sessionStatus = isLive ? t('flow.log.live') : isLatest ? t('flow.log.ended') : t('flow.log.history')
  const goSession = (n: number) => {
    if (n < 1 || n > sessionCount) return
    onSessionChange?.(n >= sessionCount ? null : n)
  }

  const commitDraft = () => {
    setEditing(false)
    const n = parseInt(draft, 10)
    if (!Number.isFinite(n)) {
      setDraft(String(session))
      return
    }
    const clamped = Math.min(sessionCount, Math.max(1, Math.trunc(n)))
    setDraft(String(clamped))
    if (clamped !== session) goSession(clamped)
  }

  return (
    <div className="vh-task-log" data-log-window="100">
      <div className="vh-log-bar">
        <span className="vh-log-bar-label">{t('flow.log.title')}</span>
        <span className="vh-log-pager">
          <Button
            type="button"
            variant="outline"
            size="icon-xs"
            className="vh-log-pager-btn"
            disabled={session <= 1}
            aria-label={t('flow.log.prevRound')}
            onClick={() => goSession(session - 1)}
          >
            ‹
          </Button>
          <span className={'vh-log-pager-status' + (isLive ? ' live' : '')}>
            {t('flow.log.roundPrefix')}
            <Input
              className="vh-log-pager-input"
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              aria-label={t('flow.log.jumpRound')}
              value={draft}
              size={Math.max(2, String(sessionCount).length)}
              onFocus={(e) => {
                setEditing(true)
                e.currentTarget.select()
              }}
              onChange={(e) => setDraft(e.target.value.replace(/\D/g, ''))}
              onBlur={() => {
                if (skipBlurCommit.current) {
                  skipBlurCommit.current = false
                  setEditing(false)
                  return
                }
                commitDraft()
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  skipBlurCommit.current = true
                  commitDraft()
                  e.currentTarget.blur()
                } else if (e.key === 'Escape') {
                  skipBlurCommit.current = true
                  setDraft(String(session))
                  setEditing(false)
                  e.currentTarget.blur()
                }
              }}
            />
            {t('flow.log.roundStatus', { count: sessionCount, status: sessionStatus })}
          </span>
          <Button
            type="button"
            variant="outline"
            size="icon-xs"
            className="vh-log-pager-btn"
            disabled={session >= sessionCount}
            aria-label={t('flow.log.nextRound')}
            onClick={() => goSession(session + 1)}
          >
            ›
          </Button>
        </span>
        <span className="vh-log-count">
          {t('flow.log.recent', { n: visible.length })}
          {moreHidden ? t('flow.log.loadOlder') : ''}
          {loadingOlder ? t('flow.log.loading') : ''}
        </span>
      </div>
      <div className="vh-log-wrap">
        <div
          ref={ref}
          className="vh-log"
          onScroll={onScroll}
          onWheel={onWheel}
          style={{ minHeight, maxHeight: Math.max(minHeight, 560) }}
        >
          {visible.length === 0 ? (
            <div className="vh-log-empty">{t('flow.log.empty')}</div>
          ) : (
            visible.map((ev, i) => (
              <LogLine key={ev.seq != null ? `s${ev.seq}` : `${ev.ts || i}-${ev.kind}-${i}`} ev={ev} />
            ))
          )}
        </div>
        {showJump ? (
          <Button type="button" variant="outline" size="sm" className="vh-jump-btn" onClick={jumpToBottom}>
            {t('flow.log.jumpLatest')}
          </Button>
        ) : null}
      </div>
    </div>
  )
}
