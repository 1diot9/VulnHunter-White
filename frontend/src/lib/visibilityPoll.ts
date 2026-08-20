/**
 * Run `tick` immediately and on an interval, pausing while the tab is hidden.
 * `tick` must return its Promise so overlapping polls wait; otherwise inFlight
 * clears immediately and stale responses can overwrite newer data.
 */
export function startVisibilityPoll(tick: () => void | Promise<void>, ms: number): () => void {
  let timer: ReturnType<typeof setInterval> | null = null
  let inFlight = false
  let stopped = false

  const runTick = () => {
    if (inFlight || stopped) return
    inFlight = true
    Promise.resolve()
      .then(() => tick())
      .catch(() => undefined)
      .finally(() => {
        inFlight = false
      })
  }

  const clear = () => {
    if (timer != null) {
      clearInterval(timer)
      timer = null
    }
  }

  const start = () => {
    clear()
    timer = setInterval(() => {
      if (!document.hidden) runTick()
    }, ms)
  }

  const onVisibility = () => {
    if (document.hidden) {
      clear()
    } else {
      runTick()
      start()
    }
  }

  runTick()
  if (!document.hidden) start()
  document.addEventListener('visibilitychange', onVisibility)

  return () => {
    stopped = true
    clear()
    document.removeEventListener('visibilitychange', onVisibility)
  }
}
