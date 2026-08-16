/** Run `tick` immediately and on an interval, pausing while the tab is hidden. */
export function startVisibilityPoll(tick: () => void | Promise<void>, ms: number): () => void {
  let timer: ReturnType<typeof setInterval> | null = null
  let inFlight = false

  const runTick = () => {
    if (inFlight) return
    inFlight = true
    Promise.resolve(tick())
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
    clear()
    document.removeEventListener('visibilitychange', onVisibility)
  }
}
