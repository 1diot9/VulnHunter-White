import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api'

export type RuntimeInfo = {
  runtime: 'host' | 'docker'
  dockerLabBuildEnabled: boolean
  manualLabAllowed: boolean
  loaded: boolean
}

const DEFAULT: RuntimeInfo = {
  runtime: 'host',
  dockerLabBuildEnabled: true,
  manualLabAllowed: true,
  loaded: false,
}

const RuntimeContext = createContext<RuntimeInfo>(DEFAULT)

export function RuntimeProvider({ children }: { children: ReactNode }) {
  const [info, setInfo] = useState<RuntimeInfo>(DEFAULT)

  useEffect(() => {
    let cancelled = false
    api
      .health()
      .then((body) => {
        if (cancelled) return
        const runtime = body.runtime === 'docker' ? 'docker' : 'host'
        setInfo({
          runtime,
          dockerLabBuildEnabled: body.docker_lab_build_enabled !== false && runtime !== 'docker',
          manualLabAllowed: body.manual_lab_allowed !== false,
          loaded: true,
        })
      })
      .catch(() => {
        if (cancelled) return
        setInfo({ ...DEFAULT, loaded: true })
      })
    return () => {
      cancelled = true
    }
  }, [])

  const value = useMemo(() => info, [info])
  return <RuntimeContext.Provider value={value}>{children}</RuntimeContext.Provider>
}

export function useRuntime(): RuntimeInfo {
  return useContext(RuntimeContext)
}
