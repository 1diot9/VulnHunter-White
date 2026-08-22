import { createContext, useCallback, useContext, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { LockIcon } from 'lucide-react'
import { api, getAccessToken, setAccessToken, subscribeAuth } from '../api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type AuthState = {
  required: boolean
  unlocked: boolean
  lock: () => void
}

const AuthContext = createContext<AuthState>({
  required: false,
  unlocked: true,
  lock: () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}

export default function AuthGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false)
  const [required, setRequired] = useState(false)
  const [unlocked, setUnlocked] = useState(false)
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [backendError, setBackendError] = useState('')

  const checkAuth = useCallback(async () => {
    setBackendError('')
    try {
      const status = await api.authStatus()
      setRequired(status.required)
      if (!status.required) {
        setUnlocked(true)
        setReady(true)
        return
      }
      const stored = getAccessToken()
      if (!stored) {
        setUnlocked(false)
        setReady(true)
        return
      }
      try {
        await api.authLogin(stored)
        setUnlocked(true)
      } catch {
        setUnlocked(false)
      }
      setReady(true)
    } catch {
      setUnlocked(false)
      setRequired(true)
      setBackendError('无法连接后端，请确认服务已启动。')
      setReady(true)
    }
  }, [])

  useEffect(() => {
    void checkAuth()
    return subscribeAuth(() => {
      void checkAuth()
    })
  }, [checkAuth])

  const lock = useCallback(() => {
    setAccessToken('')
    setUnlocked(false)
    setRequired(true)
    setToken('')
    setError('')
  }, [])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    const value = token.trim()
    if (!value) {
      setError('请输入访问令牌')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.authLogin(value)
      setAccessToken(value)
      setUnlocked(true)
      setRequired(true)
      setToken('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setUnlocked(false)
    } finally {
      setBusy(false)
    }
  }

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        加载中…
      </div>
    )
  }

  if (required && !unlocked) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4 text-foreground">
        <Card className="w-full max-w-md">
          <CardContent className="space-y-4 p-6">
            <div className="flex items-center gap-2">
              <LockIcon className="size-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">访问令牌</h1>
            </div>
            <p className="text-sm text-muted-foreground">
              {backendError || '输入访问令牌后才能查看数据或调用功能。令牌可在 .env 的 VULNHUNTER_ACCESS_TOKEN 中配置，也可在设置页修改。'}
            </p>
            {backendError ? (
              <Button type="button" onClick={() => void checkAuth()}>
                重试
              </Button>
            ) : (
              <form className="space-y-3" onSubmit={(e) => void onSubmit(e)}>
                <div className="space-y-1.5">
                  <Label htmlFor="access-token">令牌</Label>
                  <Input
                    id="access-token"
                    type="password"
                    autoFocus
                    autoComplete="current-password"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="访问令牌"
                  />
                </div>
                {error ? <div className="text-sm text-red-300">{error}</div> : null}
                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? '校验中…' : '进入'}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    )
  }

  return <AuthContext.Provider value={{ required, unlocked, lock }}>{children}</AuthContext.Provider>
}
