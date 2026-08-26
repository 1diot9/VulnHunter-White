import { useEffect, useMemo, useState } from 'react'
import { api, setAccessToken, type Settings } from '../api'
import { CustomAuditModesCard } from '../components/CustomAuditModesCard'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

const domesticEndpointHints = [
  {
    name: '智谱 BigModel',
    endpoint: 'https://open.bigmodel.cn/api/paas/v4',
    models: 'glm-5.3, glm-4-plus, glm-4-air',
    note: 'GLM Coding Plan 使用 https://open.bigmodel.cn/api/coding/paas/v4。glm-4.5 / glm-5 思考链会回传给后续轮次。',
  },
  {
    name: 'DeepSeek',
    endpoint: 'https://api.deepseek.com',
    models: 'deepseek-chat, deepseek-reasoner',
    note: '官方 OpenAI 兼容接口。deepseek-reasoner / R1 会自动省略 temperature，并保留思考链。',
  },
  {
    name: '阿里云百炼 DashScope',
    endpoint: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    models: 'qwen-plus, qwen-max, qwen-turbo',
    note: '使用 OpenAI 兼容模式。qwen3 / qwq 思考链会回传给后续轮次。',
  },
  {
    name: '月之暗面 Kimi',
    endpoint: 'https://api.moonshot.cn/v1',
    models: 'kimi-k3, kimi-k2.5, moonshot-v1-32k',
    note: '官方 OpenAI 兼容接口。kimi-k3 / k2.5+ 锁定 temperature，本项目会自动省略该参数。',
  },
  {
    name: '火山方舟 Doubao',
    endpoint: 'https://ark.cn-beijing.volces.com/api/v3',
    models: 'doubao-seed-1-6, doubao-1-5-pro-32k',
    note: '模型名通常填方舟模型或推理接入点 ID',
  },
  {
    name: '腾讯混元',
    endpoint: 'https://api.hunyuan.cloud.tencent.com/v1',
    models: 'hunyuan-turbos-latest, hunyuan-lite',
    note: '官方 OpenAI 兼容接口',
  },
  {
    name: 'MiniMax',
    endpoint: 'https://api.minimax.chat/v1',
    models: 'abab6.5s-chat, MiniMax-Text-01',
    note: '官方 OpenAI 兼容接口',
  },
  {
    name: '百川智能',
    endpoint: 'https://api.baichuan-ai.com/v1',
    models: 'Baichuan4, Baichuan3-Turbo',
    note: '官方 OpenAI 兼容接口',
  },
  {
    name: '零一万物',
    endpoint: 'https://api.lingyiwanwu.com/v1',
    models: 'yi-lightning, yi-large',
    note: '官方 OpenAI 兼容接口',
  },
  {
    name: '阶跃星辰 StepFun',
    endpoint: 'https://api.stepfun.com/v1',
    models: 'step-2-16k, step-1-8k',
    note: '官方 OpenAI 兼容接口',
  },
  {
    name: '讯飞星火',
    endpoint: 'https://spark-api-open.xf-yun.com/v1',
    models: 'generalv3.5, 4.0Ultra',
    note: 'OpenAI 兼容入口，具体模型名以控制台为准',
  },
  {
    name: '硅基流动 SiliconFlow',
    endpoint: 'https://api.siliconflow.cn/v1',
    models: 'Qwen/Qwen2.5-72B-Instruct, deepseek-ai/DeepSeek-V3',
    note: '聚合平台，模型名通常带组织前缀',
  },
  {
    name: '魔搭 ModelScope',
    endpoint: 'https://api-inference.modelscope.cn/v1',
    models: 'Qwen/Qwen2.5-72B-Instruct',
    note: '模型名以 ModelScope 控制台/API 文档为准',
  },
]

const anthropicEndpointHints = [
  {
    name: 'Anthropic 官方 Claude',
    endpoint: 'https://api.anthropic.com/v1',
    models: 'claude-sonnet-4-5, claude-opus-4-1',
    note: '官方 Anthropic Messages 接口',
  },
  {
    name: '智谱 BigModel Anthropic',
    endpoint: 'https://open.bigmodel.cn/api/anthropic/v1',
    models: 'glm-5.1, glm-4.5, glm-4.5-air',
    note: '本项目会追加 /messages；如官方文档写 /api/anthropic，这里保留 /v1。',
  },
  {
    name: 'Kimi Anthropic',
    endpoint: 'https://api.moonshot.cn/anthropic/v1',
    models: 'kimi-k3, kimi-k2-0711-preview, kimi-latest',
    note: '本项目会追加 /messages；Claude Code 文档中的 /anthropic 在这里写成 /anthropic/v1。kimi-k3 会自动省略 temperature。',
  },
  {
    name: 'Kimi Coding Plan',
    endpoint: 'https://api.kimi.com/coding/v1',
    models: 'kimi-k3, kimi-k2.5, kimi-k2-0711-preview',
    note: '订阅制 Coding Key 与通用平台 Key 可能不通用，请按 Kimi 控制台说明选择。kimi-k3 / k2.5+ 会自动省略 temperature。',
  },
  {
    name: '阿里云百炼 DashScope',
    endpoint: 'https://dashscope.aliyuncs.com/apps/anthropic/v1',
    models: 'qwen-max, qwen-plus, qwen-coder-plus',
    note: '本项目会追加 /messages；如使用业务空间专属域名，将主机替换为 {WorkspaceId}.cn-beijing.maas.aliyuncs.com。',
  },
  {
    name: 'OpenModel 聚合',
    endpoint: 'https://api.openmodel.ai/v1',
    models: 'kimi-k2.5, qwen3-max, deepseek-v4-flash, MiniMax-M2.5',
    note: '聚合平台，模型名以平台文档和账号权限为准。',
  },
]

export default function SettingsPage() {
  const [s, setS] = useState<Settings | null>(null)
  const [defaultModel, setDefaultModel] = useState('')
  const [endpoints, setEndpoints] = useState<
    Array<{ id: string; base_url: string; api_key: string; api_key_set: boolean; max_inflight: number }>
  >([{ id: 'ep-1', base_url: '', api_key: '', api_key_set: false, max_inflight: 6 }])
  const [wireApi, setWireApi] = useState<'chat' | 'anthropic'>('chat')
  const [githubPat, setGithubPat] = useState('')
  const [fofaKey, setFofaKey] = useState('')
  const [fofaBaseUrl, setFofaBaseUrl] = useState('https://fofa.info')
  const [contextWindow, setContextWindow] = useState(128000)
  const [httpProxy, setHttpProxy] = useState('')
  const [chatProxy, setChatProxy] = useState('')
  const [cliToolsDir, setCliToolsDir] = useState('tools/cli')
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

  useEffect(() => {
    api.getSettings().then((x) => {
      setS(x)
      setDefaultModel(x.default_model || '')
      const provider = x.llm_providers?.find((p) => p.id === 'default') || x.llm_providers?.[0]
      setWireApi(provider?.wire_api === 'anthropic' ? 'anthropic' : 'chat')
      const eps =
        x.llm_endpoints?.length > 0
          ? x.llm_endpoints
          : [
              {
                id: 'ep-1',
                base_url: x.default_base_url || '',
                api_key_set: x.default_api_key_set,
                max_inflight: x.llm_thread_limit || 6,
              },
            ]
      setEndpoints(
        eps.map((ep, i) => ({
          id: ep.id || `ep-${i + 1}`,
          base_url: ep.base_url || '',
          api_key: '',
          api_key_set: !!ep.api_key_set,
          max_inflight: Math.max(1, ep.max_inflight || 6),
        })),
      )
      setContextWindow(x.context_window || 128000)
      setFofaBaseUrl(x.fofa_base_url || 'https://fofa.info')
      setHttpProxy(x.http_proxy || '')
      setChatProxy(x.chat_proxy || '')
      setCliToolsDir(x.cli_tools_dir || 'tools/cli')
    })
  }, [])

  const filteredModels = useMemo(() => {
    const q = modelFilter.trim().toLowerCase()
    if (!q) return models
    return models.filter((m) => m.toLowerCase().includes(q))
  }, [models, modelFilter])

  const totalThreadLimit = useMemo(
    () => endpoints.reduce((sum, ep) => sum + Math.max(1, ep.max_inflight || 1), 0),
    [endpoints],
  )

  function probeBody(endpointId?: string) {
    const ep =
      (endpointId ? endpoints.find((e) => e.id === endpointId) : null) || endpoints[0]
    const body: { base_url?: string; api_key?: string; model?: string; wire_api?: string } = {
      wire_api: wireApi,
    }
    if (ep?.base_url.trim()) body.base_url = ep.base_url.trim()
    if (ep?.api_key.trim()) body.api_key = ep.api_key.trim()
    if (defaultModel.trim()) body.model = defaultModel.trim()
    return body
  }

  function updateEndpoint(
    id: string,
    patch: Partial<{ base_url: string; api_key: string; max_inflight: number }>,
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
        { id: `ep-${n}`, base_url: '', api_key: '', api_key_set: false, max_inflight: 6 },
      ]
    })
  }

  function removeEndpoint(id: string) {
    setEndpoints((prev) => (prev.length <= 1 ? prev : prev.filter((ep) => ep.id !== id)))
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

  async function testConn(endpointId?: string) {
    setTesting(true)
    setProbeOk(null)
    setProbeMsg('')
    setProbeEndpointId(endpointId || endpoints[0]?.id || null)
    try {
      const out = await api.testLlm(probeBody(endpointId))
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
        setGithubMsg(out.error || '连通失败')
        return
      }
      const parts = ['连通正常']
      if (out.authenticated && out.login) parts.push(`账号 ${out.login}`)
      else parts.push('匿名')
      if (out.rate_remaining != null && out.rate_limit != null) {
        parts.push(`限额 ${out.rate_remaining}/${out.rate_limit}`)
      }
      if (out.latency_ms != null) parts.push(`${out.latency_ms}ms`)
      setGithubOk(true)
      setGithubMsg(parts.join(' · '))
    } catch (e) {
      setGithubOk(false)
      setGithubMsg(String(e))
    } finally {
      setGithubTesting(false)
    }
  }

  async function save() {
    setMsg('')
    try {
      const first = endpoints[0]
      const body: Record<string, unknown> = {
        default_model: defaultModel,
        default_base_url: first?.base_url?.trim() || '',
        llm_thread_limit: totalThreadLimit,
        context_window: contextWindow,
        http_proxy: httpProxy.trim(),
        chat_proxy: chatProxy.trim(),
        cli_tools_dir: cliToolsDir.trim() || 'tools/cli',
        llm_endpoints: endpoints.map((ep) => ({
          id: ep.id,
          base_url: ep.base_url.trim(),
          api_key: ep.api_key.trim() ? ep.api_key.trim() : null,
          max_inflight: Math.max(1, ep.max_inflight || 1),
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
            max_inflight: Math.max(1, ep.max_inflight || 1),
          })),
        },
      ]
      body.llm_roles = {
        recon: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
        worker: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
        reviewer: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
        verifier: { provider_id: 'default', model: defaultModel, reasoning_effort: '' },
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
                max_inflight: next.llm_thread_limit || 6,
              },
            ]
      setEndpoints(
        nextEps.map((ep, i) => ({
          id: ep.id || `ep-${i + 1}`,
          base_url: ep.base_url || '',
          api_key: '',
          api_key_set: !!ep.api_key_set,
          max_inflight: Math.max(1, ep.max_inflight || 6),
        })),
      )
      setGithubPat('')
      setFofaKey('')
      setMsg('已保存')
    } catch (e) {
      setMsg(String(e))
    }
  }

  const logDaysSafe = Number.isFinite(logDays) ? Math.max(0, Math.min(3650, Math.floor(logDays))) : 7

  async function saveAccessToken() {
    setTokenMsg('')
    setTokenOk(null)
    if (newToken.trim() && newToken.trim() !== confirmToken.trim()) {
      setTokenOk(false)
      setTokenMsg('两次输入的新令牌不一致')
      return
    }
    if (s?.access_token_set && !currentToken.trim()) {
      setTokenOk(false)
      setTokenMsg('修改令牌需要填写当前令牌')
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
      setTokenMsg(next.access_token_set ? '访问令牌已更新' : '已清除设置中的令牌覆盖')
    } catch (e) {
      setTokenOk(false)
      setTokenMsg(String(e instanceof Error ? e.message : e))
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
          logDaysSafe === 0 ? '没有可清理的实时日志。' : `没有 ${logDaysSafe} 天前的实时日志。`,
        )
      } else {
        setLogMsg(
          `已删除 ${out.files} 个文件，涉及 ${out.projects} 个项目，共 ${formatBytes(out.bytes)}。`,
        )
      }
      setLogConfirmOpen(false)
    } catch (e) {
      setLogOk(false)
      setLogMsg(String(e))
    } finally {
      setLogPurging(false)
    }
  }

  if (!s) return <div className="text-slate-400">加载中…</div>

  const endpointHints = wireApi === 'anthropic' ? anthropicEndpointHints : domesticEndpointHints
  const endpointHelpTitle =
    wireApi === 'anthropic' ? '常见 Anthropic Messages 端点' : '常见国产模型通用端点'
  const endpointHelpDescription =
    wireApi === 'anthropic'
      ? '这些地址填在 API Base URL；本项目会在地址后追加 /messages。默认模型填写对应模型名或平台接入点 ID。'
      : '这些地址填在 API Base URL；默认模型填写对应模型名或控制台里的接入点 ID。各厂商可能调整模型名，最终以官方控制台为准。'

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <h1 className="text-2xl font-semibold">设置</h1>
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label>
              访问令牌 {s.access_token_set ? '（已配置）' : '（未配置）'}
            </Label>
            <div className="text-xs text-slate-500">
              配置后打开前端需先输入令牌才能查看数据或调用功能。可在 .env 写入
              VULNHUNTER_ACCESS_TOKEN；设置页修改后以设置为准。已配置时必须填写当前令牌。新令牌留空则清除本页覆盖，改回使用
              .env。
            </div>
            {s.access_token_set ? (
              <div className="space-y-1.5">
                <Label htmlFor="current-access-token">当前令牌</Label>
                <Input
                  id="current-access-token"
                  type="password"
                  autoComplete="current-password"
                  value={currentToken}
                  onChange={(e) => setCurrentToken(e.target.value)}
                  placeholder="原令牌"
                />
              </div>
            ) : null}
            <div className="space-y-1.5">
              <Label htmlFor="new-access-token">新令牌</Label>
              <Input
                id="new-access-token"
                type="password"
                autoComplete="new-password"
                value={newToken}
                onChange={(e) => setNewToken(e.target.value)}
                placeholder={s.access_token_set ? '至少 4 个字符，留空则清除覆盖' : '至少 4 个字符'}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm-access-token">确认新令牌</Label>
              <Input
                id="confirm-access-token"
                type="password"
                autoComplete="new-password"
                value={confirmToken}
                onChange={(e) => setConfirmToken(e.target.value)}
                placeholder="再输入一次新令牌"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" disabled={tokenSaving} onClick={() => void saveAccessToken()}>
                {tokenSaving ? '保存中…' : '更新令牌'}
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
          <Label>接口协议</Label>
          <Select
            value={wireApi}
            onValueChange={(value) => {
              if (value === 'anthropic' || value === 'chat') setWireApi(value)
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue>
                {wireApi === 'anthropic' ? 'Anthropic Messages' : 'OpenAI Chat Completions'}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="chat">OpenAI Chat Completions</SelectItem>
              <SelectItem value="anthropic">Anthropic Messages</SelectItem>
            </SelectContent>
          </Select>
          <div className="text-xs text-slate-500">
            {wireApi === 'anthropic'
              ? '走 POST /messages：system 独立字段，工具为 tool_use / tool_result。适用于官方 Claude 及兼容 Anthropic Messages 的中转。'
              : '走 POST /chat/completions。适用于 OpenAI 及兼容 Chat Completions 的模型商。'}
          </div>
        </div>
        <div className="space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <Label>模型商池（Base URL）</Label>
            <Button type="button" variant="ghost" size="sm" onClick={() => setEndpointHelpOpen(true)}>
              {wireApi === 'anthropic' ? 'Anthropic 端点' : '国产模型端点'}
            </Button>
          </div>
          <div className="text-xs text-slate-500">
            可添加多个 Base URL 扩展并行线程。会话粘滞到同一 URL；429 / 额度用尽时该端点冷却并自动换路。合计上限 = 各端点并发之和（当前 {totalThreadLimit}）。
          </div>
          <div className="space-y-3">
            {endpoints.map((ep, index) => (
              <div
                key={ep.id}
                className="space-y-2 rounded-lg border border-foreground/10 bg-muted/20 p-3"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-muted-foreground">
                    端点 {index + 1}
                    <span className="ml-1.5 tabular-nums opacity-70">{ep.id}</span>
                  </span>
                  {endpoints.length > 1 ? (
                    <Button type="button" variant="ghost" size="sm" onClick={() => removeEndpoint(ep.id)}>
                      删除
                    </Button>
                  ) : null}
                </div>
                <Input
                  value={ep.base_url}
                  onChange={(e) => updateEndpoint(ep.id, { base_url: e.target.value })}
                  placeholder={
                    wireApi === 'anthropic' ? 'https://api.anthropic.com/v1' : 'https://api.openai.com/v1'
                  }
                />
                <div className="grid gap-2 sm:grid-cols-[1fr_7rem]">
                  <Input
                    type="password"
                    value={ep.api_key}
                    onChange={(e) => updateEndpoint(ep.id, { api_key: e.target.value })}
                    placeholder={ep.api_key_set ? '已配置，留空不改' : 'sk-...'}
                  />
                  <Input
                    type="number"
                    min={1}
                    value={ep.max_inflight}
                    onChange={(e) =>
                      updateEndpoint(ep.id, {
                        max_inflight: Math.max(1, Number(e.target.value) || 1),
                      })
                    }
                    title="该端点最大并发"
                    placeholder="并发"
                  />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={listing || testing}
                    onClick={() => void fetchModels(ep.id)}
                  >
                    {listing && probeEndpointId === ep.id ? '拉取中…' : '拉取模型'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={listing || testing}
                    onClick={() => void testConn(ep.id)}
                  >
                    {testing && probeEndpointId === ep.id ? '测试中…' : '连通测试'}
                  </Button>
                  <span className="text-xs text-slate-500">并发 {ep.max_inflight}</span>
                </div>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" onClick={addEndpoint}>
              添加 Base URL
            </Button>
            <span className="text-xs text-slate-400">合计线程上限 {totalThreadLimit}</span>
          </div>
          {wireApi === 'chat' ? (
            <div className="text-xs text-slate-500">
              智谱 BigModel 通用端点填 https://open.bigmodel.cn/api/paas/v4；GLM Coding Plan 填
              https://open.bigmodel.cn/api/coding/paas/v4，不要填 /api/v1。
            </div>
          ) : null}
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
            {probeMsg ? (
              <div className="flex items-start gap-2 text-sm">
                {probeOk != null ? <Badge variant={probeOk ? 'success' : 'destructive'}>{probeOk ? '成功' : '失败'}</Badge> : null}
                <span className={probeOk === false ? 'text-red-300' : 'text-slate-300'}>
                  {probeEndpointId ? `[${probeEndpointId}] ` : ''}
                  {probeMsg}
                </span>
              </div>
            ) : (
              <div className="text-xs text-slate-500">
                {wireApi === 'anthropic'
                  ? '各端点可单独拉取 / 连通测试。拉取走 GET /models，连通测试发一条极短 POST /messages。均使用当前表单值，不会自动保存。'
                  : '各端点可单独拉取 / 连通测试。拉取走 GET /models，连通测试发一条极短 chat/completions。均使用当前表单值，不会自动保存。'}
              </div>
            )}
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
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" disabled={githubTesting} onClick={testGithub}>
              {githubTesting ? '测试中…' : '连通测试'}
            </Button>
          </div>
          {githubMsg ? (
            <div className="flex items-start gap-2 text-sm">
              {githubOk != null ? <Badge variant={githubOk ? 'success' : 'destructive'}>{githubOk ? '成功' : '失败'}</Badge> : null}
              <span className={githubOk === false ? 'text-red-300' : 'text-slate-300'}>{githubMsg}</span>
            </div>
          ) : (
            <div className="text-xs text-slate-500">
              连通测试访问 api.github.com。有 PAT 则校验令牌与额度，无 PAT 则测匿名访问（GHSA / Issues）。使用当前表单的 PAT 与出站代理，不会自动保存。
            </div>
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
        <div className="space-y-1.5">
          <Label>出站代理（WebSearch / GHSA / GitHub Issues / FOFA）</Label>
          <Input
            value={httpProxy}
            onChange={(e) => setHttpProxy(e.target.value)}
            placeholder="留空则直连，例如 http://127.0.0.1:10808"
          />
          <div className="text-xs text-slate-500">
            仅工具出站 HTTP 使用。保存空值表示直连。代理连不上时自动改走直连。
          </div>
        </div>
        <div className="space-y-1.5">
          <Label>Chat 代理</Label>
          <Input
            value={chatProxy}
            onChange={(e) => setChatProxy(e.target.value)}
            placeholder="留空则 Chat Completions 直连"
          />
          <div className="text-xs text-slate-500">代理不可用时自动直连，不必先清空。</div>
        </div>
        <div className="space-y-1.5">
          <Label>CLI 工具目录</Label>
          <Input
            value={cliToolsDir}
            onChange={(e) => setCliToolsDir(e.target.value)}
            placeholder="tools/cli"
          />
          <div className="text-xs text-slate-500">
            Reviewer 用 SearchTools 搜索这里已索引的 CLI。每个子目录是一个工具。相对路径相对仓库根目录。后台轮询扫描，静默 Agent（最多 30 轮）生成描述；日志写在该子目录的 agent.log.jsonl。
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={save}>保存</Button>
          {msg ? <span className="text-sm text-slate-300">{msg}</span> : null}
        </div>
        </CardContent>
      </Card>
      <CustomAuditModesCard />
      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label>实时日志清理</Label>
            <div className="text-xs text-slate-500">
              清理各审计项目的 SSE 实时日志（live-events）。按文件最后写入时间判断，近期仍在更新的日志不会被删。填 0 表示清除全部实时日志。阶段报告、漏洞与源码不受影响。
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="space-y-1.5">
                <Label htmlFor="log-days">清除多少天前</Label>
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
                清理日志
              </Button>
            </div>
            {logMsg ? (
              <div className="flex items-start gap-2 text-sm">
                {logOk != null ? (
                  <Badge variant={logOk ? 'success' : 'destructive'}>{logOk ? '完成' : '失败'}</Badge>
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
            <DialogTitle>清理实时日志</DialogTitle>
            <DialogDescription>
              {logDaysSafe === 0
                ? '将删除所有审计项目的全部实时日志（SSE）。此操作不可恢复。'
                : `将删除所有审计项目中 ${logDaysSafe} 天前的实时日志（SSE），近期日志不受影响。此操作不可恢复。`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={logPurging} onClick={() => setLogConfirmOpen(false)}>
              取消
            </Button>
            <Button variant="destructive" disabled={logPurging} onClick={() => void confirmPurgeLogs()}>
              {logPurging ? '清理中…' : '确认清理'}
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
                    <div className="font-medium text-slate-100">{item.name}</div>
                    <div className="mt-1 break-all font-mono text-xs text-sky-300">{item.endpoint}</div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setEndpoints((prev) => {
                        if (!prev.length) {
                          return [
                            {
                              id: 'ep-1',
                              base_url: item.endpoint,
                              api_key: '',
                              api_key_set: false,
                              max_inflight: 6,
                            },
                          ]
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
                    填入
                  </Button>
                </div>
                <div className="mt-2 text-xs text-slate-400">模型示例：{item.models}</div>
                <div className="mt-1 text-xs text-slate-500">{item.note}</div>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
