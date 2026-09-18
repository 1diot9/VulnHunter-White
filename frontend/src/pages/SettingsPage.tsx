import { useEffect, useMemo, useState } from 'react'
import { api, formatApiError, setAccessToken, type LlmEndpointUsage, type Settings } from '../api'
import { CustomAuditModesCard } from '../components/CustomAuditModesCard'
import { AppUpdateCard } from '../components/AppUpdatePanel'
import { endpointCooldownReason, endpointSkipLabel } from '../components/LlmThreadUsageBar'
import { useI18n } from '@/i18n'
import { startVisibilityPoll } from '../lib/visibilityPoll'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

type EndpointHint = {
  name: string
  nameKey?: string
  endpoint: string
  models: string
  noteKey: string
}

const domesticEndpointHints: EndpointHint[] = [
  {
    name: '智谱 BigModel',
    endpoint: 'https://open.bigmodel.cn/api/paas/v4',
    models: 'glm-5.3, glm-4-plus, glm-4-air',
    noteKey: 'settings.note.zhipu',
  },
  {
    name: 'DeepSeek',
    endpoint: 'https://api.deepseek.com',
    models: 'deepseek-chat, deepseek-reasoner',
    noteKey: 'settings.note.deepseek',
  },
  {
    name: '阿里云百炼 DashScope',
    endpoint: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    models: 'qwen-plus, qwen-max, qwen-turbo',
    noteKey: 'settings.note.dashscope',
  },
  {
    name: '月之暗面 Kimi',
    endpoint: 'https://api.moonshot.cn/v1',
    models: 'kimi-k3, kimi-k2.5, moonshot-v1-32k',
    noteKey: 'settings.note.kimi',
  },
  {
    name: '火山方舟 Doubao',
    endpoint: 'https://ark.cn-beijing.volces.com/api/v3',
    models: 'doubao-seed-1-6, doubao-1-5-pro-32k',
    noteKey: 'settings.note.doubao',
  },
  {
    name: '腾讯混元',
    endpoint: 'https://api.hunyuan.cloud.tencent.com/v1',
    models: 'hunyuan-turbos-latest, hunyuan-lite',
    noteKey: 'settings.note.openaiCompat',
  },
  {
    name: 'MiniMax',
    endpoint: 'https://api.minimax.chat/v1',
    models: 'abab6.5s-chat, MiniMax-Text-01',
    noteKey: 'settings.note.openaiCompat',
  },
  {
    name: '百川智能',
    endpoint: 'https://api.baichuan-ai.com/v1',
    models: 'Baichuan4, Baichuan3-Turbo',
    noteKey: 'settings.note.openaiCompat',
  },
  {
    name: '零一万物',
    endpoint: 'https://api.lingyiwanwu.com/v1',
    models: 'yi-lightning, yi-large',
    noteKey: 'settings.note.openaiCompat',
  },
  {
    name: '阶跃星辰 StepFun',
    endpoint: 'https://api.stepfun.com/v1',
    models: 'step-2-16k, step-1-8k',
    noteKey: 'settings.note.openaiCompat',
  },
  {
    name: '讯飞星火',
    endpoint: 'https://spark-api-open.xf-yun.com/v1',
    models: 'generalv3.5, 4.0Ultra',
    noteKey: 'settings.note.spark',
  },
  {
    name: '硅基流动 SiliconFlow',
    endpoint: 'https://api.siliconflow.cn/v1',
    models: 'Qwen/Qwen2.5-72B-Instruct, deepseek-ai/DeepSeek-V3',
    noteKey: 'settings.note.siliconflow',
  },
  {
    name: '魔搭 ModelScope',
    endpoint: 'https://api-inference.modelscope.cn/v1',
    models: 'Qwen/Qwen2.5-72B-Instruct',
    noteKey: 'settings.note.modelscope',
  },
]

const anthropicEndpointHints: EndpointHint[] = [
  {
    name: 'Anthropic 官方 Claude',
    nameKey: 'settings.vendor.anthropicOfficial',
    endpoint: 'https://api.anthropic.com/v1',
    models: 'claude-sonnet-4-5, claude-opus-4-1',
    noteKey: 'settings.note.anthropicOfficial',
  },
  {
    name: '智谱 BigModel Anthropic',
    endpoint: 'https://open.bigmodel.cn/api/anthropic/v1',
    models: 'glm-5.1, glm-4.5, glm-4.5-air',
    noteKey: 'settings.note.zhipuAnthropic',
  },
  {
    name: 'Kimi Anthropic',
    endpoint: 'https://api.moonshot.cn/anthropic/v1',
    models: 'kimi-k3, kimi-k2-0711-preview, kimi-latest',
    noteKey: 'settings.note.kimiAnthropic',
  },
  {
    name: 'Kimi Coding Plan',
    endpoint: 'https://api.kimi.com/coding/v1',
    models: 'kimi-k3, kimi-k2.5, kimi-k2-0711-preview',
    noteKey: 'settings.note.kimiCoding',
  },
  {
    name: '阿里云百炼 DashScope',
    endpoint: 'https://dashscope.aliyuncs.com/apps/anthropic/v1',
    models: 'qwen-max, qwen-plus, qwen-coder-plus',
    noteKey: 'settings.note.dashscopeAnthropic',
  },
  {
    name: 'OpenModel 聚合',
    nameKey: 'settings.vendor.openmodel',
    endpoint: 'https://api.openmodel.ai/v1',
    models: 'kimi-k2.5, qwen3-max, deepseek-v4-flash, MiniMax-M2.5',
    noteKey: 'settings.note.openmodel',
  },
]

const responsesEndpointHints: EndpointHint[] = [
  {
    name: 'OpenAI 官方',
    nameKey: 'settings.vendor.openaiOfficial',
    endpoint: 'https://api.openai.com/v1',
    models: 'gpt-5, gpt-4.1, o4-mini',
    noteKey: 'settings.note.openaiOfficial',
  },
  {
    name: 'OpenRouter',
    endpoint: 'https://openrouter.ai/api/v1',
    models: 'openai/gpt-5, openai/gpt-4.1',
    noteKey: 'settings.note.openrouter',
  },
]

type WireApi = 'chat' | 'responses' | 'anthropic'
type EndpointWire = '' | WireApi

type EndpointDraft = {
  id: string
  base_url: string
  api_key: string
  api_key_set: boolean
  model: string
  wire_api: EndpointWire
  max_inflight: number
  weight: number
  disabled: boolean
}

function parseWireApi(value: string | undefined | null): WireApi {
  if (value === 'anthropic' || value === 'responses') return value
  return 'chat'
}

function parseEndpointWire(value: string | undefined | null): EndpointWire {
  if (value === 'anthropic' || value === 'responses' || value === 'chat') return value
  return ''
}

function wireApiLabel(wire: WireApi): string {
  if (wire === 'anthropic') return 'Anthropic Messages'
  if (wire === 'responses') return 'OpenAI Responses'
  return 'OpenAI Chat Completions'
}

function clampWeight(value: number | undefined | null): number {
  const n = Number(value)
  if (!Number.isFinite(n)) return 1
  if (n <= 0) return 0.01
  return Math.min(1, Math.round(n * 100) / 100)
}

function emptyEndpoint(id: string, model = ''): EndpointDraft {
  return {
    id,
    base_url: '',
    api_key: '',
    api_key_set: false,
    model,
    wire_api: '',
    max_inflight: 6,
    weight: 1,
    disabled: false,
  }
}

function draftFromApi(
  ep: {
    id?: string
    base_url?: string
    api_key_set?: boolean
    model?: string
    wire_api?: string
    max_inflight?: number
    weight?: number
    disabled?: boolean
  },
  index: number,
): EndpointDraft {
  return {
    id: ep.id || `ep-${index + 1}`,
    base_url: ep.base_url || '',
    api_key: '',
    api_key_set: !!ep.api_key_set,
    model: ep.model || '',
    wire_api: parseEndpointWire(ep.wire_api),
    max_inflight: Math.max(1, ep.max_inflight || 6),
    weight: clampWeight(ep.weight),
    disabled: !!ep.disabled,
  }
}

export default function SettingsPage() {
  const { t } = useI18n()
  const [s, setS] = useState<Settings | null>(null)
  const [defaultModel, setDefaultModel] = useState('')
  const [endpoints, setEndpoints] = useState<EndpointDraft[]>([emptyEndpoint('ep-1')])
  const [wireApi, setWireApi] = useState<WireApi>('chat')
  const [githubPat, setGithubPat] = useState('')
  const [fofaKey, setFofaKey] = useState('')
  const [fofaBaseUrl, setFofaBaseUrl] = useState('https://fofa.info')
  const [contextWindow, setContextWindow] = useState(128000)
  const [minRequestInterval, setMinRequestInterval] = useState(2)
  const [httpProxy, setHttpProxy] = useState('')
  const [chatProxy, setChatProxy] = useState('')
  const [cliToolsDir, setCliToolsDir] = useState('tools/cli')
  const [jadxPath, setJadxPath] = useState('')
  const [jadxTesting, setJadxTesting] = useState(false)
  const [jadxOk, setJadxOk] = useState<boolean | null>(null)
  const [jadxMsg, setJadxMsg] = useState('')
  const [codegraphPath, setCodegraphPath] = useState('')
  const [codegraphTesting, setCodegraphTesting] = useState(false)
  const [codegraphOk, setCodegraphOk] = useState<boolean | null>(null)
  const [codegraphMsg, setCodegraphMsg] = useState('')
  const [msg, setMsg] = useState('')
  const [models, setModels] = useState<string[]>([])
  const [modelFilter, setModelFilter] = useState('')
  const [listing, setListing] = useState(false)
  const [testing, setTesting] = useState(false)
  const [probeOk, setProbeOk] = useState<boolean | null>(null)
  const [probeMsg, setProbeMsg] = useState('')
  const [probeEndpointId, setProbeEndpointId] = useState<string | null>(null)
  const [fofaTesting, setFofaTesting] = useState(false)
  const [fofaOk, setFofaOk] = useState<boolean | null>(null)
  const [fofaMsg, setFofaMsg] = useState('')
  const [githubTesting, setGithubTesting] = useState(false)
  const [githubOk, setGithubOk] = useState<boolean | null>(null)
  const [githubMsg, setGithubMsg] = useState('')
  const [logDays, setLogDays] = useState(7)
  const [logConfirmOpen, setLogConfirmOpen] = useState(false)
  const [logPurging, setLogPurging] = useState(false)
  const [logMsg, setLogMsg] = useState('')
  const [logOk, setLogOk] = useState<boolean | null>(null)
  const [endpointHelpOpen, setEndpointHelpOpen] = useState(false)
  const [currentToken, setCurrentToken] = useState('')
  const [newToken, setNewToken] = useState('')
  const [confirmToken, setConfirmToken] = useState('')
  const [tokenMsg, setTokenMsg] = useState('')
  const [tokenOk, setTokenOk] = useState<boolean | null>(null)
  const [tokenSaving, setTokenSaving] = useState(false)
  const [epUsage, setEpUsage] = useState<LlmEndpointUsage[]>([])

  useEffect(
    () =>
      startVisibilityPoll(() => {
        return api
          .llmThreadUsage()
          .then((u) => setEpUsage(u.endpoints || []))
          .catch(() => {})
      }, 2000),
    [],
  )

  const usageById = useMemo(() => {
    const m = new Map<string, LlmEndpointUsage>()
    for (const ep of epUsage) m.set(ep.id, ep)
    return m
  }, [epUsage])

  useEffect(() => {
    api.getSettings().then((x) => {
      setS(x)
      setDefaultModel(x.default_model || '')
      const provider = x.llm_providers?.find((p) => p.id === 'default') || x.llm_providers?.[0]
      setWireApi(parseWireApi(provider?.wire_api))
      const eps =
        x.llm_endpoints?.length > 0
          ? x.llm_endpoints
          : [
              {
                id: 'ep-1',
                base_url: x.default_base_url || '',
                api_key_set: x.default_api_key_set,
                model: x.default_model || '',
                max_inflight: x.llm_thread_limit || 6,
                disabled: false,
              },
            ]
      setEndpoints(eps.map((ep, i) => draftFromApi(ep, i)))
      if (!x.default_model && eps[0]?.model) {
        setDefaultModel(eps[0].model)
      }
      setContextWindow(x.context_window || 128000)
      setMinRequestInterval(
        Number.isFinite(x.llm_min_request_interval_sec) ? x.llm_min_request_interval_sec : 2,
      )
      setFofaBaseUrl(x.fofa_base_url || 'https://fofa.info')
      setHttpProxy(x.http_proxy || '')
      setChatProxy(x.chat_proxy || '')
      setCliToolsDir(x.cli_tools_dir || 'tools/cli')
      setJadxPath(x.jadx_path || '')
      setCodegraphPath(x.codegraph_path || '')
    })
  }, [])

  const filteredModels = useMemo(() => {
    const q = modelFilter.trim().toLowerCase()
    if (!q) return models
    return models.filter((m) => m.toLowerCase().includes(q))
  }, [models, modelFilter])

  const totalThreadLimit = useMemo(
    () =>
      endpoints.reduce(
        (sum, ep) => (ep.disabled ? sum : sum + Math.max(1, ep.max_inflight || 1)),
        0,
      ),
    [endpoints],
  )
  const enabledCount = useMemo(
    () => endpoints.filter((ep) => !ep.disabled).length,
    [endpoints],
  )

  function probeBody(endpointId?: string) {
    const ep =
      (endpointId ? endpoints.find((e) => e.id === endpointId) : null) || endpoints[0]
    const body: {
      endpoint_id?: string
      base_url?: string
      api_key?: string
      model?: string
      wire_api?: string
    } = {
      wire_api: ep?.wire_api || wireApi,
    }
    if (ep?.id) body.endpoint_id = ep.id
    if (ep?.base_url.trim()) body.base_url = ep.base_url.trim()
    if (ep?.api_key.trim()) body.api_key = ep.api_key.trim()
    const model = (ep?.model || defaultModel).trim()
    if (model) body.model = model
    return body
  }

  function updateEndpoint(
    id: string,
    patch: Partial<{
      base_url: string
      api_key: string
      model: string
      wire_api: EndpointWire
      max_inflight: number
      weight: number
      disabled: boolean
    }>,
  ) {
    setEndpoints((prev) => prev.map((ep) => (ep.id === id ? { ...ep, ...patch } : ep)))
  }

  function addEndpoint() {
    setEndpoints((prev) => {
      const used = new Set(prev.map((e) => e.id))
      let n = prev.length + 1
      while (used.has(`ep-${n}`)) n += 1
      return [
        ...prev,
        emptyEndpoint(`ep-${n}`, defaultModel.trim()),
      ]
    })
  }

  function removeEndpoint(id: string) {
    setEndpoints((prev) => {
      if (prev.length <= 1) return prev
      const target = prev.find((ep) => ep.id === id)
      if (!target) return prev
      const enabledLeft = prev.filter((ep) => ep.id !== id && !ep.disabled).length
      if (!target.disabled && enabledLeft < 1) return prev
      return prev.filter((ep) => ep.id !== id)
    })
  }

  async function fetchModels(endpointId?: string) {
    setListing(true)
    setProbeOk(null)
    setProbeMsg('')
    setProbeEndpointId(endpointId || endpoints[0]?.id || null)
    try {
      const out = await api.listLlmModels(probeBody(endpointId))
      if (!out.ok) {
        setModels([])
        setProbeOk(false)
        setProbeMsg(out.error || t('settings.fetch.fail'))
        return
      }
      setModels(out.models)
      setModelFilter('')
      const targetId = endpointId || endpoints[0]?.id
      if (targetId && !endpoints.find((e) => e.id === targetId)?.model.trim() && out.models.length === 1) {
        updateEndpoint(targetId, { model: out.models[0] })
      }
      if (!defaultModel.trim() && out.models.length === 1) {
        setDefaultModel(out.models[0])
      }
      const latency = out.latency_ms != null ? ` · ${out.latency_ms}ms` : ''
      setProbeOk(true)
      setProbeMsg(t('settings.fetch.ok', { count: out.count, latency }))
    } catch (e) {
      setModels([])
      setProbeOk(false)
      setProbeMsg(formatApiError(e, t('settings.fetch.timeout')))
    } finally {
      setListing(false)
    }
  }

  async function testConn(endpointId?: string) {
    setTesting(true)
    setProbeOk(null)
    setProbeMsg('')
    setProbeEndpointId(endpointId || endpoints[0]?.id || null)
    try {
      const out = await api.testLlm(probeBody(endpointId))
      if (!out.ok) {
        setProbeOk(false)
        setProbeMsg(out.error || t('settings.conn.fail'))
        return
      }
      const extraParts: string[] = []
      if (out.latency_ms != null) extraParts.push(`${out.latency_ms}ms`)
      if (out.reply) extraParts.push(t('settings.conn.reply', { reply: out.reply }))
      const extra = extraParts.length ? ` · ${extraParts.join(' · ')}` : ''
      setProbeOk(true)
      setProbeMsg(t('settings.conn.ok', { model: out.model, extra }))
    } catch (e) {
      setProbeOk(false)
      setProbeMsg(formatApiError(e, t('settings.conn.timeout')))
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
        setFofaMsg(out.error || t('settings.conn.fail'))
        return
      }
      const parts = [t('settings.status.ok')]
      if (out.username) parts.push(t('settings.status.account', { name: out.username }))
      if (out.fcoin != null) parts.push(t('settings.status.fcoin', { n: out.fcoin }))
      if (out.isvip) parts.push('VIP')
      if (out.latency_ms != null) parts.push(`${out.latency_ms}ms`)
      setFofaOk(true)
      setFofaMsg(parts.join(' · '))
    } catch (e) {
      setFofaOk(false)
      setFofaMsg(formatApiError(e, t('settings.fofa.timeout')))
    } finally {
      setFofaTesting(false)
    }
  }

  async function testGithub() {
    setGithubTesting(true)
    setGithubOk(null)
    setGithubMsg('')
    try {
      const body: { github_pat?: string; http_proxy: string } = {
        http_proxy: httpProxy.trim(),
      }
      if (githubPat.trim()) body.github_pat = githubPat.trim()
      const out = await api.testGithub(body)
      if (!out.ok) {
        setGithubOk(false)
        setGithubMsg(out.error || t('settings.conn.fail'))
        return
      }
      const parts = [t('settings.status.ok')]
      if (out.authenticated && out.login) parts.push(t('settings.status.account', { name: out.login }))
      else parts.push(t('settings.status.anonymous'))
      if (out.rate_remaining != null && out.rate_limit != null) {
        parts.push(t('settings.status.rate', { remaining: out.rate_remaining, limit: out.rate_limit }))
      }
      if (out.latency_ms != null) parts.push(`${out.latency_ms}ms`)
      setGithubOk(true)
      setGithubMsg(parts.join(' · '))
    } catch (e) {
      setGithubOk(false)
      setGithubMsg(formatApiError(e, t('settings.github.timeout')))
    } finally {
      setGithubTesting(false)
    }
  }

  async function testJadx() {
    setJadxTesting(true)
    setJadxOk(null)
    setJadxMsg('')
    try {
      const body: { jadx_path?: string } = {}
      if (jadxPath.trim()) body.jadx_path = jadxPath.trim()
      const out = await api.testJadx(body)
      if (!out.ok) {
        setJadxOk(false)
        setJadxMsg(out.error || t('settings.jadx.fail'))
        return
      }
      const parts = [out.version || t('settings.jadx.available')]
      if (out.path) parts.push(out.path)
      if (out.latency_ms != null) parts.push(`${out.latency_ms}ms`)
      setJadxOk(true)
      setJadxMsg(parts.join(' · '))
    } catch (e) {
      setJadxOk(false)
      setJadxMsg(formatApiError(e, t('settings.jadx.timeout')))
    } finally {
      setJadxTesting(false)
    }
  }

  async function testCodegraph() {
    setCodegraphTesting(true)
    setCodegraphOk(null)
    setCodegraphMsg('')
    try {
      const body: { codegraph_path?: string } = {}
      if (codegraphPath.trim()) body.codegraph_path = codegraphPath.trim()
      const out = await api.testCodegraph(body)
      if (!out.ok) {
        setCodegraphOk(false)
        setCodegraphMsg(out.error || t('settings.codegraph.missing'))
        return
      }
      setCodegraphOk(true)
      setCodegraphMsg([out.path, out.version, out.latency_ms != null ? `${out.latency_ms}ms` : '']
        .filter(Boolean)
        .join(' · '))
    } catch (e) {
      setCodegraphOk(false)
      setCodegraphMsg(formatApiError(e, t('settings.codegraph.timeout')))
    } finally {
      setCodegraphTesting(false)
    }
  }

  async function save() {
    setMsg('')
    try {
      const first = endpoints.find((ep) => !ep.disabled) || endpoints[0]
      const body: Record<string, unknown> = {
        default_model: defaultModel,
        default_base_url: first?.base_url?.trim() || '',
        llm_thread_limit: totalThreadLimit,
        llm_min_request_interval_sec: Math.max(
          0,
          Math.min(60, Number(minRequestInterval) || 0),
        ),
        context_window: contextWindow,
        http_proxy: httpProxy.trim(),
        chat_proxy: chatProxy.trim(),
        cli_tools_dir: cliToolsDir.trim() || 'tools/cli',
        jadx_path: jadxPath.trim(),
        codegraph_path: codegraphPath.trim(),
        llm_endpoints: endpoints.map((ep) => ({
          id: ep.id,
          base_url: ep.base_url.trim(),
          api_key: ep.api_key.trim() ? ep.api_key.trim() : null,
          model: ep.model.trim(),
          wire_api: ep.wire_api,
          max_inflight: Math.max(1, ep.max_inflight || 1),
          weight: clampWeight(ep.weight),
          disabled: !!ep.disabled,
        })),
      }
      if (githubPat.trim()) body.github_pat = githubPat.trim()
      if (fofaKey.trim()) body.fofa_key = fofaKey.trim()
      if (fofaBaseUrl.trim()) body.fofa_base_url = fofaBaseUrl.trim()
      body.llm_providers = [
        {
          id: 'default',
          name: 'Default',
          base_url: first?.base_url?.trim() || '',
          wire_api: wireApi,
          env_key: wireApi === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY',
          api_key: first?.api_key?.trim() || null,
          endpoints: endpoints.map((ep) => ({
            id: ep.id,
            base_url: ep.base_url.trim(),
            api_key: ep.api_key.trim() ? ep.api_key.trim() : null,
            model: ep.model.trim(),
            wire_api: ep.wire_api,
            max_inflight: Math.max(1, ep.max_inflight || 1),
            weight: clampWeight(ep.weight),
            disabled: !!ep.disabled,
          })),
        },
      ]
      const roleModel = defaultModel.trim() || first?.model?.trim() || ''
      body.llm_roles = {
        recon: { provider_id: 'default', model: roleModel, reasoning_effort: '' },
        worker: { provider_id: 'default', model: roleModel, reasoning_effort: '' },
        reviewer: { provider_id: 'default', model: roleModel, reasoning_effort: '' },
        verifier: { provider_id: 'default', model: roleModel, reasoning_effort: '' },
      }
      const next = await api.putSettings(body)
      setS(next)
      const nextEps =
        next.llm_endpoints?.length > 0
          ? next.llm_endpoints
          : [
              {
                id: 'ep-1',
                base_url: next.default_base_url || '',
                api_key_set: next.default_api_key_set,
                model: next.default_model || '',
                max_inflight: next.llm_thread_limit || 6,
                disabled: false,
              },
            ]
      setEndpoints(nextEps.map((ep, i) => draftFromApi(ep, i)))
      const nextProvider = next.llm_providers?.find((p) => p.id === 'default') || next.llm_providers?.[0]
      if (nextProvider?.wire_api) setWireApi(parseWireApi(nextProvider.wire_api))
      if (next.default_model) setDefaultModel(next.default_model)
      if (Number.isFinite(next.llm_min_request_interval_sec)) {
        setMinRequestInterval(next.llm_min_request_interval_sec)
      }
      setGithubPat('')
      setFofaKey('')
      setMsg(t('common.saved'))
    } catch (e) {
      setMsg(formatApiError(e))
    }
  }

  const logDaysSafe = Number.isFinite(logDays) ? Math.max(0, Math.min(3650, Math.floor(logDays))) : 7

  async function saveAccessToken() {
    setTokenMsg('')
    setTokenOk(null)
    if (newToken.trim() && newToken.trim() !== confirmToken.trim()) {
      setTokenOk(false)
      setTokenMsg(t('settings.token.mismatch'))
      return
    }
    if (s?.access_token_set && !currentToken.trim()) {
      setTokenOk(false)
      setTokenMsg(t('settings.token.needCurrent'))
      return
    }
    setTokenSaving(true)
    try {
      const next = await api.updateAccessToken(currentToken, newToken)
      setS(next)
      if (newToken.trim()) {
        setAccessToken(newToken.trim())
      } else if (!next.access_token_set) {
        setAccessToken('')
      } else if (currentToken.trim()) {
        setAccessToken(currentToken.trim())
      }
      setCurrentToken('')
      setNewToken('')
      setConfirmToken('')
      setTokenOk(true)
      setTokenMsg(next.access_token_set ? t('settings.token.updated') : t('settings.token.cleared'))
    } catch (e) {
      setTokenOk(false)
      setTokenMsg(formatApiError(e))
    } finally {
      setTokenSaving(false)
    }
  }

  async function confirmPurgeLogs() {
    setLogPurging(true)
    setLogMsg('')
    setLogOk(null)
    try {
      const out = await api.purgeLiveLogs(logDaysSafe)
      setLogOk(true)
      if (out.files === 0) {
        setLogMsg(
          logDaysSafe === 0
            ? t('settings.log.emptyAll')
            : t('settings.log.emptyDays', { days: logDaysSafe }),
        )
      } else {
        setLogMsg(
          t('settings.log.deleted', {
            files: out.files,
            projects: out.projects,
            size: formatBytes(out.bytes),
          }),
        )
      }
      setLogConfirmOpen(false)
    } catch (e) {
      setLogOk(false)
      setLogMsg(formatApiError(e, t('settings.log.timeout')))
    } finally {
      setLogPurging(false)
    }
  }

  if (!s) return <div className="text-slate-400">{t('common.loading')}</div>

  const endpointHints =
    wireApi === 'anthropic'
      ? anthropicEndpointHints
      : wireApi === 'responses'
        ? responsesEndpointHints
        : domesticEndpointHints
  const endpointHelpTitle =
    wireApi === 'anthropic'
      ? t('settings.help.title.anthropic')
      : wireApi === 'responses'
        ? t('settings.help.title.responses')
        : t('settings.help.title.chat')
  const endpointHelpDescription =
    wireApi === 'anthropic'
      ? t('settings.help.desc.anthropic')
      : wireApi === 'responses'
        ? t('settings.help.desc.responses')
        : t('settings.help.desc.chat')

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <h1 className="text-2xl font-semibold">{t('settings.title')}</h1>
      <AppUpdateCard />
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label>
              {s.access_token_set ? t('settings.token.configured') : t('settings.token.unset')}
            </Label>
            <div className="text-xs text-slate-500">{t('settings.token.hint')}</div>
            {s.access_token_set ? (
              <div className="space-y-1.5">
                <Label htmlFor="current-access-token">{t('settings.token.current')}</Label>
                <Input
                  id="current-access-token"
                  type="password"
                  autoComplete="current-password"
                  value={currentToken}
                  onChange={(e) => setCurrentToken(e.target.value)}
                  placeholder={t('settings.token.currentPlaceholder')}
                />
              </div>
            ) : null}
            <div className="space-y-1.5">
              <Label htmlFor="new-access-token">{t('settings.token.new')}</Label>
              <Input
                id="new-access-token"
                type="password"
                autoComplete="new-password"
                value={newToken}
                onChange={(e) => setNewToken(e.target.value)}
                placeholder={s.access_token_set ? t('settings.token.placeholderClear') : t('settings.token.placeholderMin')}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm-access-token">{t('settings.token.confirm')}</Label>
              <Input
                id="confirm-access-token"
                type="password"
                autoComplete="new-password"
                value={confirmToken}
                onChange={(e) => setConfirmToken(e.target.value)}
                placeholder={t('settings.token.confirmPlaceholder')}
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" disabled={tokenSaving} onClick={() => void saveAccessToken()}>
                {tokenSaving ? t('settings.token.saving') : t('settings.token.update')}
              </Button>
              {tokenMsg ? (
                <span className={tokenOk === false ? 'text-sm text-red-300' : 'text-sm text-slate-300'}>
                  {tokenMsg}
                </span>
              ) : null}
            </div>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="space-y-3 p-4">
        <div className="space-y-1.5">
          <Label>{t('settings.wire.label')}</Label>
          <Select
            value={wireApi}
            onValueChange={(value) => {
              if (value === 'anthropic' || value === 'chat' || value === 'responses') {
                setWireApi(value)
              }
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue>{wireApiLabel(wireApi)}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="chat">OpenAI Chat Completions</SelectItem>
              <SelectItem value="responses">OpenAI Responses</SelectItem>
              <SelectItem value="anthropic">Anthropic Messages</SelectItem>
            </SelectContent>
          </Select>
          <div className="text-xs text-slate-500">
            {wireApi === 'anthropic'
              ? t('settings.wire.hint.anthropic')
              : wireApi === 'responses'
                ? t('settings.wire.hint.responses')
                : t('settings.wire.hint.chat')}
          </div>
        </div>
        <div className="space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <Label>{t('settings.pool.label')}</Label>
            <Button type="button" variant="ghost" size="sm" onClick={() => setEndpointHelpOpen(true)}>
              {wireApi === 'anthropic'
                ? t('settings.pool.btn.anthropic')
                : wireApi === 'responses'
                  ? t('settings.pool.btn.responses')
                  : t('settings.pool.btn.chat')}
            </Button>
          </div>
          <div className="text-xs text-slate-500">
            {t('settings.pool.hint', { limit: totalThreadLimit })}
          </div>
          <div className="flex max-w-xs items-center gap-2">
            <Label className="shrink-0 whitespace-nowrap">{t('settings.pool.interval')}</Label>
            <Input
              type="number"
              min={0}
              max={60}
              step={0.5}
              value={minRequestInterval}
              onChange={(e) => {
                const n = Number(e.target.value)
                setMinRequestInterval(Number.isFinite(n) ? n : 0)
              }}
              title={t('settings.pool.intervalTitle')}
            />
          </div>
          <div className="space-y-3">
            {endpoints.map((ep, index) => (
              <div
                key={ep.id}
                className={`space-y-2 rounded-lg border border-foreground/10 bg-muted/20 p-3${ep.disabled ? ' opacity-60' : ''}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-muted-foreground">
                    {t('settings.pool.endpoint', { n: index + 1 })}
                    <span className="ml-1.5 tabular-nums opacity-70">{ep.id}</span>
                    {ep.disabled ? <span className="ml-1.5 text-red-300">{t('llm.disabled')}</span> : null}
                  </span>
                  <div className="flex items-center gap-2">
                    <Label className="flex items-center gap-1.5 text-xs font-normal text-muted-foreground">
                      <Checkbox
                        checked={ep.disabled}
                        disabled={!ep.disabled && enabledCount <= 1}
                        title={
                          !ep.disabled && enabledCount <= 1
                            ? t('settings.pool.disableKeepOne')
                            : t('settings.pool.disableHint')
                        }
                        onCheckedChange={(checked) =>
                          updateEndpoint(ep.id, { disabled: checked === true })
                        }
                      />
                      {t('settings.pool.disable')}
                    </Label>
                    {endpoints.length > 1 ? (
                      <Button type="button" variant="ghost" size="sm" onClick={() => removeEndpoint(ep.id)}>
                        {t('common.delete')}
                      </Button>
                    ) : null}
                  </div>
                </div>
                <EndpointHealthLine health={usageById.get(ep.id)} />
                <div className="space-y-1">
                  <Label className="text-xs font-normal text-muted-foreground">{t('settings.pool.wire')}</Label>
                  <Select
                    value={ep.wire_api || '__inherit__'}
                    onValueChange={(value) => {
                      if (value === '__inherit__' || value == null) {
                        updateEndpoint(ep.id, { wire_api: '' })
                        return
                      }
                      if (value === 'chat' || value === 'responses' || value === 'anthropic') {
                        updateEndpoint(ep.id, { wire_api: value })
                      }
                    }}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue>
                        {ep.wire_api
                          ? wireApiLabel(ep.wire_api)
                          : t('settings.wire.inherit', { label: wireApiLabel(wireApi) })}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__inherit__">{t('settings.wire.inherit', { label: wireApiLabel(wireApi) })}</SelectItem>
                      <SelectItem value="chat">OpenAI Chat Completions</SelectItem>
                      <SelectItem value="responses">OpenAI Responses</SelectItem>
                      <SelectItem value="anthropic">Anthropic Messages</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Input
                  value={ep.base_url}
                  onChange={(e) => updateEndpoint(ep.id, { base_url: e.target.value })}
                  placeholder={
                    (ep.wire_api || wireApi) === 'anthropic'
                      ? 'https://api.anthropic.com/v1'
                      : 'https://api.openai.com/v1'
                  }
                />
                <div className="grid gap-2 sm:grid-cols-[1fr_minmax(8rem,1fr)_6.5rem_5.5rem]">
                  <Input
                    type="password"
                    className="self-end"
                    value={ep.api_key}
                    onChange={(e) => updateEndpoint(ep.id, { api_key: e.target.value })}
                    placeholder={ep.api_key_set ? t('settings.pool.keySet') : 'sk-...'}
                  />
                  <Input
                    className="self-end"
                    value={ep.model}
                    onChange={(e) => updateEndpoint(ep.id, { model: e.target.value })}
                    placeholder={defaultModel.trim() || t('settings.pool.modelName')}
                    title={t('settings.pool.modelTitle')}
                  />
                  <div className="space-y-1">
                    <Label className="text-xs font-normal text-muted-foreground">
                      {t('settings.pool.inflightPlaceholder')}
                    </Label>
                    <Input
                      type="number"
                      min={1}
                      value={ep.max_inflight}
                      onChange={(e) =>
                        updateEndpoint(ep.id, {
                          max_inflight: Math.max(1, Number(e.target.value) || 1),
                        })
                      }
                      title={t('settings.pool.inflightTitle')}
                      placeholder={t('settings.pool.inflightPlaceholder')}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs font-normal text-muted-foreground">
                      {t('settings.pool.weightPlaceholder')}
                    </Label>
                    <Input
                      type="number"
                      min={0.01}
                      max={1}
                      step={0.1}
                      value={ep.weight}
                      onChange={(e) =>
                        updateEndpoint(ep.id, { weight: clampWeight(Number(e.target.value)) })
                      }
                      title={t('settings.pool.weightTitle')}
                      placeholder={t('settings.pool.weightPlaceholder')}
                    />
                  </div>
                </div>
                {models.length > 0 && probeEndpointId === ep.id ? (
                  <>
                    {models.length > 20 ? (
                      <Input
                        value={modelFilter}
                        onChange={(e) => setModelFilter(e.target.value)}
                        placeholder={t('settings.pool.filterModels', { n: models.length })}
                      />
                    ) : null}
                    <Select
                      value={models.includes(ep.model) ? ep.model : '__none__'}
                      onValueChange={(value) => {
                        if (value == null || value === '__none__') return
                        updateEndpoint(ep.id, { model: value })
                      }}
                    >
                      <SelectTrigger className="w-full">
                        <SelectValue>
                          {models.includes(ep.model)
                            ? ep.model
                            : t('settings.pool.selectFromList', {
                                filtered: filteredModels.length,
                                total: models.length,
                              })}
                        </SelectValue>
                      </SelectTrigger>
                      <SelectContent alignItemWithTrigger={false} align="start" className="max-h-72 w-(--anchor-width)">
                        <SelectItem value="__none__">
                          {t('settings.pool.selectFromList', {
                            filtered: filteredModels.length,
                            total: models.length,
                          })}
                        </SelectItem>
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
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={listing || testing}
                    onClick={() => void fetchModels(ep.id)}
                  >
                    {listing && probeEndpointId === ep.id ? t('settings.pool.listing') : t('settings.pool.fetchModels')}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={listing || testing}
                    onClick={() => void testConn(ep.id)}
                  >
                    {testing && probeEndpointId === ep.id ? t('settings.pool.testing') : t('settings.pool.testConn')}
                  </Button>
                  <span className="text-xs text-slate-500">
                    {ep.model.trim() || defaultModel.trim() || t('settings.pool.noModel')} ·{' '}
                    {t('settings.pool.concurrency', { n: ep.max_inflight })}
                    {' · '}
                    {t('settings.pool.weightValue', { n: ep.weight })}
                    {ep.disabled ? t('settings.pool.notAllocated') : ''}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" onClick={addEndpoint}>
              {t('settings.pool.addUrl')}
            </Button>
            <span className="text-xs text-slate-400">{t('settings.pool.totalLimit', { n: totalThreadLimit })}</span>
          </div>
          {wireApi === 'chat' ? (
            <div className="text-xs text-slate-500">{t('settings.pool.zhipuHint')}</div>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.fallbackModel')}</Label>
          <div className="space-y-2">
            <Input
              value={defaultModel}
              onChange={(e) => setDefaultModel(e.target.value)}
              placeholder="gpt-4o"
            />
            <div className="text-xs text-slate-500">{t('settings.fallbackHint')}</div>
            {probeMsg ? (
              <div className="flex items-start gap-2 text-sm">
                {probeOk != null ? (
                  <Badge variant={probeOk ? 'success' : 'destructive'}>
                    {probeOk ? t('common.success') : t('common.fail')}
                  </Badge>
                ) : null}
                <span className={probeOk === false ? 'text-red-300' : 'text-slate-300'}>
                  {probeEndpointId ? `[${probeEndpointId}] ` : ''}
                  {probeMsg}
                </span>
              </div>
            ) : (
              <div className="text-xs text-slate-500">
                {wireApi === 'anthropic'
                  ? t('settings.probe.hint.anthropic')
                  : wireApi === 'responses'
                    ? t('settings.probe.hint.responses')
                    : t('settings.probe.hint.chat')}
              </div>
            )}
          </div>
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.contextWindow')}</Label>
          <Input
            type="number"
            value={contextWindow}
            onChange={(e) => setContextWindow(Number(e.target.value) || 128000)}
          />
        </div>
        <div className="space-y-1.5">
          <Label>
            {s.github_pat_set ? t('settings.github.configured') : t('settings.github.private')}
          </Label>
          <Input
            type="password"
            value={githubPat}
            onChange={(e) => setGithubPat(e.target.value)}
            placeholder="ghp_..."
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" disabled={githubTesting} onClick={testGithub}>
              {githubTesting ? t('settings.pool.testing') : t('settings.pool.testConn')}
            </Button>
          </div>
          {githubMsg ? (
            <div className="flex items-start gap-2 text-sm">
              {githubOk != null ? (
                <Badge variant={githubOk ? 'success' : 'destructive'}>
                  {githubOk ? t('common.success') : t('common.fail')}
                </Badge>
              ) : null}
              <span className={githubOk === false ? 'text-red-300' : 'text-slate-300'}>{githubMsg}</span>
            </div>
          ) : (
            <div className="text-xs text-slate-500">{t('settings.github.hint')}</div>
          )}
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
            {s.fofa_key_set ? t('settings.fofa.configured') : t('settings.fofa.verifier')}
          </Label>
          <Input
            type="password"
            value={fofaKey}
            onChange={(e) => setFofaKey(e.target.value)}
            placeholder="FOFA API key"
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" disabled={fofaTesting} onClick={testFofa}>
              {fofaTesting ? t('settings.pool.testing') : t('settings.pool.testConn')}
            </Button>
          </div>
          {fofaMsg ? (
            <div className="flex items-start gap-2 text-sm">
              {fofaOk != null ? (
                <Badge variant={fofaOk ? 'success' : 'destructive'}>
                  {fofaOk ? t('common.success') : t('common.fail')}
                </Badge>
              ) : null}
              <span className={fofaOk === false ? 'text-red-300' : 'text-slate-300'}>{fofaMsg}</span>
            </div>
          ) : (
            <div className="text-xs text-slate-500">{t('settings.fofa.hint')}</div>
          )}
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.httpProxy')}</Label>
          <Input
            value={httpProxy}
            onChange={(e) => setHttpProxy(e.target.value)}
            placeholder={t('settings.httpProxy.placeholder')}
          />
          <div className="text-xs text-slate-500">{t('settings.httpProxy.hint')}</div>
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.chatProxy')}</Label>
          <Input
            value={chatProxy}
            onChange={(e) => setChatProxy(e.target.value)}
            placeholder={t('settings.chatProxy.placeholder')}
          />
          <div className="text-xs text-slate-500">{t('settings.chatProxy.hint')}</div>
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.cliDir')}</Label>
          <Input
            value={cliToolsDir}
            onChange={(e) => setCliToolsDir(e.target.value)}
            placeholder="tools/cli"
          />
          <div className="text-xs text-slate-500">{t('settings.cliDir.hint')}</div>
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.jadx')}</Label>
          <div className="flex flex-wrap gap-2">
            <Input
              className="min-w-[16rem] flex-1"
              value={jadxPath}
              onChange={(e) => setJadxPath(e.target.value)}
              placeholder={t('settings.jadx.placeholder')}
            />
            <Button type="button" variant="outline" disabled={jadxTesting} onClick={testJadx}>
              {jadxTesting ? t('settings.jadx.detecting') : t('settings.jadx.detect')}
            </Button>
          </div>
          {jadxMsg ? (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {jadxOk != null ? (
                <Badge variant={jadxOk ? 'success' : 'destructive'}>
                  {jadxOk ? t('common.success') : t('common.fail')}
                </Badge>
              ) : null}
              <span className={jadxOk === false ? 'text-red-300' : 'text-slate-300'}>{jadxMsg}</span>
            </div>
          ) : null}
          <div className="text-xs text-slate-500">{t('settings.jadx.hint')}</div>
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.codegraph')}</Label>
          <div className="flex flex-wrap gap-2">
            <Input
              className="min-w-[16rem] flex-1"
              value={codegraphPath}
              onChange={(e) => setCodegraphPath(e.target.value)}
              placeholder={t('settings.codegraph.placeholder')}
            />
            <Button type="button" variant="outline" disabled={codegraphTesting} onClick={testCodegraph}>
              {codegraphTesting ? t('settings.jadx.detecting') : t('settings.jadx.detect')}
            </Button>
          </div>
          {codegraphMsg ? (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {codegraphOk != null ? (
                <Badge variant={codegraphOk ? 'success' : 'destructive'}>
                  {codegraphOk ? t('common.success') : t('common.fail')}
                </Badge>
              ) : null}
              <span className={codegraphOk === false ? 'text-red-300' : 'text-slate-300'}>{codegraphMsg}</span>
            </div>
          ) : null}
          <div className="text-xs text-slate-500">{t('settings.codegraph.hint')}</div>
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={save}>{t('common.save')}</Button>
          {msg ? <span className="text-sm text-slate-300">{msg}</span> : null}
        </div>
        </CardContent>
      </Card>
      <CustomAuditModesCard />
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label>{t('settings.log.title')}</Label>
            <div className="text-xs text-slate-500">{t('settings.log.hint')}</div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="space-y-1.5">
                <Label htmlFor="log-days">{t('settings.log.days')}</Label>
                <Input
                  id="log-days"
                  type="number"
                  min={0}
                  max={3650}
                  className="w-28"
                  value={logDays}
                  onChange={(e) => setLogDays(Number(e.target.value))}
                />
              </div>
              <Button
                type="button"
                variant="destructive"
                onClick={() => {
                  setLogConfirmOpen(true)
                }}
              >
                {t('settings.log.purge')}
              </Button>
            </div>
            {logMsg ? (
              <div className="flex items-start gap-2 text-sm">
                {logOk != null ? (
                  <Badge variant={logOk ? 'success' : 'destructive'}>
                    {logOk ? t('common.done') : t('common.fail')}
                  </Badge>
                ) : null}
                <span className={logOk === false ? 'text-red-300' : 'text-slate-300'}>{logMsg}</span>
              </div>
            ) : null}
          </div>
        </CardContent>
      </Card>
      <Dialog
        open={logConfirmOpen}
        onOpenChange={(next) => {
          if (logPurging) return
          setLogConfirmOpen(next)
        }}
      >
        <DialogContent showCloseButton={!logPurging}>
          <DialogHeader>
            <DialogTitle>{t('settings.log.confirmTitle')}</DialogTitle>
            <DialogDescription>
              {logDaysSafe === 0
                ? t('settings.log.confirmAll')
                : t('settings.log.confirmDays', { days: logDaysSafe })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={logPurging} onClick={() => setLogConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button variant="destructive" disabled={logPurging} onClick={() => void confirmPurgeLogs()}>
              {logPurging ? t('settings.log.purging') : t('settings.log.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={endpointHelpOpen} onOpenChange={setEndpointHelpOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{endpointHelpTitle}</DialogTitle>
            <DialogDescription>{endpointHelpDescription}</DialogDescription>
          </DialogHeader>
          <div className="max-h-[60vh] space-y-2 overflow-y-auto pr-1">
            {endpointHints.map((item) => (
              <div key={item.name} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="font-medium text-slate-100">
                      {item.nameKey ? t(item.nameKey) : item.name}
                    </div>
                    <div className="mt-1 break-all font-mono text-xs text-sky-300">{item.endpoint}</div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setEndpoints((prev) => {
                        if (!prev.length) {
                          return [{ ...emptyEndpoint('ep-1', defaultModel.trim()), base_url: item.endpoint }]
                        }
                        const emptyIdx = prev.findIndex((ep) => !ep.base_url.trim())
                        const idx = emptyIdx >= 0 ? emptyIdx : 0
                        return prev.map((ep, i) =>
                          i === idx ? { ...ep, base_url: item.endpoint } : ep,
                        )
                      })
                      setEndpointHelpOpen(false)
                    }}
                  >
                    {t('settings.help.fill')}
                  </Button>
                </div>
                <div className="mt-2 text-xs text-slate-400">{t('settings.help.models', { models: item.models })}</div>
                <div className="mt-1 text-xs text-slate-500">{t(item.noteKey)}</div>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function EndpointHealthLine({ health }: { health: LlmEndpointUsage | undefined }) {
  if (!health) return null
  const skip = endpointSkipLabel(health)
  const reason = skip ? endpointCooldownReason(health) : ''
  if (!skip) return null
  return (
    <div className="text-xs break-all">
      <span className={health.disabled ? 'text-red-300' : 'text-amber-200'}>{skip}</span>
      {reason ? <span className="mt-0.5 block whitespace-pre-wrap text-slate-400">{reason}</span> : null}
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
