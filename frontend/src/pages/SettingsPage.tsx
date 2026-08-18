import { useEffect, useMemo, useState } from 'react'
import { api, type Settings } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

export default function SettingsPage() {
  const [s, setS] = useState<Settings | null>(null)
  const [defaultModel, setDefaultModel] = useState('')
  const [defaultBaseUrl, setDefaultBaseUrl] = useState('')
  const [defaultApiKey, setDefaultApiKey] = useState('')
  const [githubPat, setGithubPat] = useState('')
  const [fofaKey, setFofaKey] = useState('')
  const [fofaBaseUrl, setFofaBaseUrl] = useState('https://fofa.info')
  const [llmThreadLimit, setLlmThreadLimit] = useState(6)
  const [contextWindow, setContextWindow] = useState(128000)
  const [msg, setMsg] = useState('')
  const [models, setModels] = useState<string[]>([])
  const [modelFilter, setModelFilter] = useState('')
  const [listing, setListing] = useState(false)
  const [testing, setTesting] = useState(false)
  const [probeOk, setProbeOk] = useState<boolean | null>(null)
  const [probeMsg, setProbeMsg] = useState('')
  const [fofaTesting, setFofaTesting] = useState(false)
  const [fofaOk, setFofaOk] = useState<boolean | null>(null)
  const [fofaMsg, setFofaMsg] = useState('')

  useEffect(() => {
    api.getSettings().then((x) => {
      setS(x)
      setDefaultModel(x.default_model || '')
      setDefaultBaseUrl(x.default_base_url || '')
      setLlmThreadLimit(x.llm_thread_limit || 6)
      setContextWindow(x.context_window || 128000)
      setFofaBaseUrl(x.fofa_base_url || 'https://fofa.info')
    })
  }, [])

  const filteredModels = useMemo(() => {
    const q = modelFilter.trim().toLowerCase()
    if (!q) return models
    return models.filter((m) => m.toLowerCase().includes(q))
  }, [models, modelFilter])

  function probeBody() {
    const body: { base_url?: string; api_key?: string; model?: string } = {}
    if (defaultBaseUrl.trim()) body.base_url = defaultBaseUrl.trim()
    if (defaultApiKey.trim()) body.api_key = defaultApiKey.trim()
    if (defaultModel.trim()) body.model = defaultModel.trim()
    return body
  }

  async function fetchModels() {
    setListing(true)
    setProbeOk(null)
    setProbeMsg('')
    try {
      const out = await api.listLlmModels(probeBody())
      if (!out.ok) {
        setModels([])
        setProbeOk(false)
        setProbeMsg(out.error || '拉取失败')
        return
      }
      setModels(out.models)
      setModelFilter('')
      if (!defaultModel.trim() && out.models.length === 1) {
        setDefaultModel(out.models[0])
      }
      const latency = out.latency_ms != null ? ` · ${out.latency_ms}ms` : ''
      setProbeOk(true)
      setProbeMsg(`已拉取 ${out.count} 个模型${latency}。请点「保存」才会写入配置。`)
    } catch (e) {
      setModels([])
      setProbeOk(false)
      setProbeMsg(String(e))
    } finally {
      setListing(false)
    }
  }

  async function testConn() {
    setTesting(true)
    setProbeOk(null)
    setProbeMsg('')
    try {
      const out = await api.testLlm(probeBody())
      if (!out.ok) {
        setProbeOk(false)
        setProbeMsg(out.error || '连通失败')
        return
      }
      const latency = out.latency_ms != null ? `${out.latency_ms}ms` : ''
      const reply = out.reply ? ` · 回复 ${out.reply}` : ''
      setProbeOk(true)
      setProbeMsg(`连通正常 · ${out.model}${latency ? ` · ${latency}` : ''}${reply}`)
    } catch (e) {
      setProbeOk(false)
      setProbeMsg(String(e))
    } finally {
      setTesting(false)
    }
  }

  async function testFofa() {
    setFofaTesting(true)
    setFofaOk(null)
    setFofaMsg('')
    try {
      const body: { key?: string; base_url?: string } = {}
      if (fofaKey.trim()) body.key = fofaKey.trim()
      if (fofaBaseUrl.trim()) body.base_url = fofaBaseUrl.trim()
      const out = await api.testFofa(body)
      if (!out.ok) {
        setFofaOk(false)
        setFofaMsg(out.error || '连通失败')
        return
      }
      const parts = ['连通正常']
      if (out.username) parts.push(`账号 ${out.username}`)
      if (out.fcoin != null) parts.push(`F点 ${out.fcoin}`)
      if (out.isvip) parts.push('VIP')
      if (out.latency_ms != null) parts.push(`${out.latency_ms}ms`)
      setFofaOk(true)
      setFofaMsg(parts.join(' · '))
    } catch (e) {
      setFofaOk(false)
      setFofaMsg(String(e))
    } finally {
      setFofaTesting(false)
    }
  }

  async function save() {
    setMsg('')
    try {
      const body: Record<string, unknown> = {
        default_model: defaultModel,
        default_base_url: defaultBaseUrl,
        llm_thread_limit: llmThreadLimit,
        context_window: contextWindow,
      }
      if (defaultApiKey.trim()) body.default_api_key = defaultApiKey.trim()
      if (githubPat.trim()) body.github_pat = githubPat.trim()
      if (fofaKey.trim()) body.fofa_key = fofaKey.trim()
      if (fofaBaseUrl.trim()) body.fofa_base_url = fofaBaseUrl.trim()
      // ensure a default provider for chat completions if base_url set
      if (defaultBaseUrl.trim()) {
        body.llm_providers = [
          {
            id: 'default',
            name: 'Default',
            base_url: defaultBaseUrl.trim(),
            wire_api: 'chat',
            env_key: 'OPENAI_API_KEY',
            api_key: defaultApiKey.trim() || null,
          },
        ]
        body.llm_roles = {
          recon: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
          worker: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
          reviewer: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
          verifier: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
        }
      }
      const next = await api.putSettings(body)
      setS(next)
      setDefaultApiKey('')
      setGithubPat('')
      setFofaKey('')
      setMsg('已保存')
    } catch (e) {
      setMsg(String(e))
    }
  }

  if (!s) return <div className="text-slate-400">加载中…</div>

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <h1 className="text-2xl font-semibold">设置</h1>
      <Card>
        <CardContent className="space-y-3 p-4">
        <div className="space-y-1.5">
          <Label>Chat Completions Base URL</Label>
          <Input value={defaultBaseUrl} onChange={(e) => setDefaultBaseUrl(e.target.value)} placeholder="https://api.openai.com/v1" />
        </div>
        <div className="space-y-1.5">
          <Label>
            API Key {s.default_api_key_set ? '（已配置，留空不改）' : ''}
          </Label>
          <Input
            type="password"
            value={defaultApiKey}
            onChange={(e) => setDefaultApiKey(e.target.value)}
            placeholder="sk-..."
          />
        </div>
        <div className="space-y-1.5">
          <Label>默认模型</Label>
          <div className="space-y-2">
            <Input
              value={defaultModel}
              onChange={(e) => setDefaultModel(e.target.value)}
              placeholder="gpt-4o"
            />
            {models.length > 0 ? (
              <>
                {models.length > 20 ? (
                  <Input
                    value={modelFilter}
                    onChange={(e) => setModelFilter(e.target.value)}
                    placeholder={`筛选 ${models.length} 个模型…`}
                  />
                ) : null}
                <Select
                  value={models.includes(defaultModel) ? defaultModel : '__none__'}
                  onValueChange={(value) => {
                    if (value == null) return
                    setDefaultModel(value === '__none__' ? '' : value)
                  }}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue>
                      {models.includes(defaultModel)
                        ? defaultModel
                        : `从清单选择（${filteredModels.length}/${models.length}）…`}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent alignItemWithTrigger={false} align="start" className="max-h-72 w-(--anchor-width)">
                  <SelectItem value="__none__">从清单选择（{filteredModels.length}/{models.length}）…</SelectItem>
                  {filteredModels.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m}
                    </SelectItem>
                  ))}
                  </SelectContent>
                </Select>
              </>
            ) : null}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" disabled={listing || testing} onClick={fetchModels}>
                {listing ? '拉取中…' : '拉取模型清单'}
              </Button>
              <Button type="button" variant="outline" disabled={listing || testing} onClick={testConn}>
                {testing ? '测试中…' : '连通测试'}
              </Button>
            </div>
            {probeMsg ? (
              <div className="flex items-start gap-2 text-sm">
                {probeOk != null ? <Badge variant={probeOk ? 'success' : 'destructive'}>{probeOk ? '成功' : '失败'}</Badge> : null}
                <span className={probeOk === false ? 'text-red-300' : 'text-slate-300'}>{probeMsg}</span>
              </div>
            ) : (
              <div className="text-xs text-slate-500">拉取走 GET /models，连通测试发一条极短 chat/completions。均使用当前表单值，不会自动保存。</div>
            )}
          </div>
        </div>
        <div className="space-y-1.5">
          <Label>总线程数</Label>
          <Input
            type="number"
            min={1}
            value={llmThreadLimit}
            onChange={(e) => setLlmThreadLimit(Math.max(1, Number(e.target.value) || 6))}
          />
          <div className="text-xs text-slate-500">
            所有运行中项目的侦察、挖掘、审核等 LLM 线程合计上限。超出的工作按到达顺序排队放行。默认 6。
          </div>
        </div>
        <div className="space-y-1.5">
          <Label>上下文窗口（token 估算上限）</Label>
          <Input
            type="number"
            value={contextWindow}
            onChange={(e) => setContextWindow(Number(e.target.value) || 128000)}
          />
        </div>
        <div className="space-y-1.5">
          <Label>
            GitHub PAT {s.github_pat_set ? '（已配置，留空不改）' : '（私有仓）'}
          </Label>
          <Input
            type="password"
            value={githubPat}
            onChange={(e) => setGithubPat(e.target.value)}
            placeholder="ghp_..."
          />
        </div>
        <div className="space-y-1.5">
          <Label>FOFA Base URL</Label>
          <Input
            value={fofaBaseUrl}
            onChange={(e) => setFofaBaseUrl(e.target.value)}
            placeholder="https://fofa.info"
          />
        </div>
        <div className="space-y-1.5">
          <Label>
            FOFA Key {s.fofa_key_set ? '（已配置，留空不改）' : '（Verifier 互联网验证）'}
          </Label>
          <Input
            type="password"
            value={fofaKey}
            onChange={(e) => setFofaKey(e.target.value)}
            placeholder="FOFA API key"
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" disabled={fofaTesting} onClick={testFofa}>
              {fofaTesting ? '测试中…' : '连通测试'}
            </Button>
          </div>
          {fofaMsg ? (
            <div className="flex items-start gap-2 text-sm">
              {fofaOk != null ? <Badge variant={fofaOk ? 'success' : 'destructive'}>{fofaOk ? '成功' : '失败'}</Badge> : null}
              <span className={fofaOk === false ? 'text-red-300' : 'text-slate-300'}>{fofaMsg}</span>
            </div>
          ) : (
            <div className="text-xs text-slate-500">
              连通测试走 FOFA info/my，校验 Key 与剩余 F 点。使用当前表单值，空 Key 则用已保存配置，不会自动保存。
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={save}>保存</Button>
          {msg ? <span className="text-sm text-slate-300">{msg}</span> : null}
        </div>
        </CardContent>
      </Card>
    </div>
  )
}
