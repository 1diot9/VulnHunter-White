import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { CheckIcon, CopyIcon, DownloadIcon, Loader2Icon } from 'lucide-react'
import { api, type VulnDetail, type VulnTrackingStatus } from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { normalizeDynamicVerifyMode } from './DynamicVerifyToggle'
import VulnFollowUpPanel from './VulnFollowUpPanel'
import {
  formatAttackSurface,
  formatDateTime,
  formatConfigPremise,
  formatMiningPath,
  formatProjectRef,
  formatSeverity,
  formatSeverityScore,
  formatSubmissionTier,
  formatTrackingStatus,
  formatVerifierStatus,
  formatVerifierTargetStatus,
  formatVulnStatus,
  saveBlob,
  severityScoreBadgeClass,
} from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const MarkdownView = lazy(() => import('./MarkdownView'))

export default function VulnDetailDialog({
  vulnId,
  onClose,
  onSelectVuln,
  projectName,
  dynamicVerifyMode,
  dynamicVerifyEnabled,
  onUpdated,
  showProjectLink = true,
}: {
  vulnId: number | null
  onClose: () => void
  onSelectVuln?: (id: number) => void
  projectName?: string
  dynamicVerifyMode?: 'off' | 'lab' | 'harness'
  dynamicVerifyEnabled?: boolean
  onUpdated?: (detail: VulnDetail) => void
  showProjectLink?: boolean
}) {
  const [detail, setDetail] = useState<VulnDetail | null>(null)
  const [marking, setMarking] = useState(false)
  const [dynamicBusy, setDynamicBusy] = useState(false)
  const [dynamicError, setDynamicError] = useState('')
  const [reportKind, setReportKind] = useState<'report' | 'advisory' | 'cve'>('report')
  const [advisoryCopied, setAdvisoryCopied] = useState(false)
  const [cveCopied, setCveCopied] = useState(false)

  useEffect(() => {
    if (vulnId == null) {
      setDetail(null)
      setDynamicError('')
      setDynamicBusy(false)
      setReportKind('report')
      setAdvisoryCopied(false)
      setCveCopied(false)
      return
    }
    setReportKind('report')
    setAdvisoryCopied(false)
    setCveCopied(false)
    setDynamicError('')
    setDynamicBusy(false)
    return startVisibilityPoll(() => {
      api.getVuln(vulnId).then(setDetail).catch(() => setDetail(null))
    }, 5000)
  }, [vulnId])

  const detailSurface = formatAttackSurface(detail?.attack_surface, detail?.required_account)
  const detailScore = formatSeverityScore(detail?.severity_score)
  const detailTier = formatSubmissionTier(detail?.submission_tier)
  const detailTracking = formatTrackingStatus(detail?.tracking_status)
  const detailVerifier = formatVerifierStatus(detail?.verifier_status)
  const detailMiningPath = formatMiningPath(detail?.mining_path)
  const detailConfigPremise = formatConfigPremise(detail?.config_premise)
  const detailProject =
    projectName ||
    detail?.project_name ||
    (detail ? `项目 ${detail.project_id}` : '')
  const detailVerifyMode = normalizeDynamicVerifyMode(dynamicVerifyMode, dynamicVerifyEnabled)
  const priorIsHarness = detail?.evidence_level === 'harness'
  const dynamicVerifyKind =
    detailVerifyMode === 'harness'
      ? '局部验证'
      : detailVerifyMode === 'lab'
        ? '靶场动态验证'
        : '靶场动态或局部验证'
  const priorConclusion = priorIsHarness ? '局部验证' : '静态'
  const dynamicVerifyHint =
    detail?.dynamic_verify_queued || dynamicBusy
      ? `已接续原审核轮次，正在${priorConclusion}结论上追加${dynamicVerifyKind}，不是互联网验证。`
      : priorIsHarness
        ? `对已局部验证确认的漏洞追加靶场动态验证，不是互联网验证。完成后证据等级会从局部验证更新为动态验证。项目须为靶场动态模式（可在项目设置中切换）。`
        : `对已仅静态确认的漏洞追加${dynamicVerifyKind}，不是互联网验证。完成后证据等级会从 static_only 更新。`

  async function downloadReport(id: number, kind: 'report' | 'advisory' | 'cve' = 'report') {
    try {
      const { blob, filename } = await api.downloadVulnReport(id, kind)
      saveBlob(blob, filename)
    } catch {
      /* ignore transient */
    }
  }

  async function copyAdvisory() {
    const text = detail?.advisory_md
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setAdvisoryCopied(true)
      window.setTimeout(() => setAdvisoryCopied(false), 1600)
    } catch {
      /* ignore */
    }
  }

  async function copyCveJson() {
    const text = detail?.cve_json
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCveCopied(true)
      window.setTimeout(() => setCveCopied(false), 1600)
    } catch {
      /* ignore */
    }
  }

  async function markDetail(tracking_status: VulnTrackingStatus) {
    if (!detail || marking) return
    setMarking(true)
    try {
      const updated = await api.updateVulnTracking(detail.id, tracking_status)
      const next = { ...detail, tracking_status: updated.tracking_status }
      setDetail(next)
      onUpdated?.(next)
    } catch {
      /* ignore transient */
    } finally {
      setMarking(false)
    }
  }

  async function startDynamicVerify() {
    if (!detail || dynamicBusy || detail.dynamic_verify_queued) return
    setDynamicBusy(true)
    setDynamicError('')
    try {
      await api.requestDynamicVerify(detail.id)
      const next = await api.getVuln(detail.id)
      setDetail(next)
      onUpdated?.(next)
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err || '')
      try {
        const data = JSON.parse(text)
        setDynamicError(String(data.detail || text))
      } catch {
        setDynamicError(text || '启动动态验证失败')
      }
    } finally {
      setDynamicBusy(false)
    }
  }

  function RelatedVulnLink({ id, children }: { id: number; children: ReactNode }) {
    if (onSelectVuln) {
      return (
        <button type="button" className="underline" onClick={() => onSelectVuln(id)}>
          {children}
        </button>
      )
    }
    return (
      <Link className="underline" to={`/vulns/${id}`}>
        {children}
      </Link>
    )
  }

  return (
    <Dialog
      open={vulnId != null}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <DialogContent className="flex max-h-[min(90vh,52rem)] w-full max-w-[calc(100%-2rem)] flex-col gap-0 overflow-hidden p-0 sm:max-w-4xl">
        <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
          <DialogTitle className="text-lg leading-snug font-semibold">
            {detail?.title || '漏洞详情'}
          </DialogTitle>
          <DialogDescription>
            {detail ? (
              <>
                {showProjectLink ? (
                  <Link className="hover:underline" to={`/projects/${detail.project_id}`}>
                    {formatProjectRef(detail.project_id, detailProject)}
                  </Link>
                ) : (
                  formatProjectRef(detail.project_id, detailProject)
                )}
                {' · '}产出时间 {formatDateTime(detail.created_at)}
              </>
            ) : (
              '加载报告…'
            )}
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-auto px-5 py-4">
          {detail ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-xs">
                <Badge variant="outline">项目 #{detail.project_id}</Badge>
                <Badge variant="outline">{detail.vuln_type}</Badge>
                <Badge variant="warning">{formatSeverity(detail.severity)}</Badge>
                {detailScore ? (
                  <Badge variant="outline" className={severityScoreBadgeClass(detail.severity_score)}>
                    {detailScore}
                  </Badge>
                ) : null}
                <Badge variant={detail.submission_tier === 'cve_candidate' ? 'info' : 'outline'}>{detailTier}</Badge>
                <Badge
                  variant={
                    detail.status === 'confirmed' || detail.status === 'static_only'
                      ? 'success'
                      : detail.status === 'false_positive'
                        ? 'destructive'
                        : 'info'
                  }
                >
                  {formatVulnStatus(detail.status, detail.evidence_level)}
                </Badge>
                {detailMiningPath ? <Badge variant="outline">{detailMiningPath}</Badge> : null}
                {detailConfigPremise ? <Badge variant="outline">{detailConfigPremise}</Badge> : null}
                {detail.tracking_status === 'submitted' || detail.tracking_status === 'ignored' ? (
                  <Badge variant={detail.tracking_status === 'submitted' ? 'info' : 'outline'}>{detailTracking}</Badge>
                ) : null}
                {detailSurface ? <Badge variant="info">{detailSurface}</Badge> : null}
                {detailVerifier ? (
                  <Badge
                    variant={
                      detail.verifier_status === 'verified'
                        ? 'success'
                        : detail.verifier_status === 'failed'
                          ? 'destructive'
                          : 'outline'
                    }
                  >
                    {detailVerifier}
                  </Badge>
                ) : null}
                {detail.verifier_verified_url ? (
                  <span className="text-xs text-slate-400">{detail.verifier_verified_url}</span>
                ) : null}
              </div>
              {detail.verifier_status === 'awaiting_user' ? (
                <div className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-100/90">
                  互联网复测可能产生危害，正在等待你在「验证确认」页跳过或给出指示后继续。
                  <Link className="ml-2 underline" to="/verifier-consent">
                    去确认
                  </Link>
                </div>
              ) : null}
              {detail.verifier_status === 'skipped' ? (
                <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                  未做互联网复测。可能因用户选择跳过、缺少可对任意 URL 复测的 HTTP PoC，或其他原因；详见下方报告「互联网验证」。
                </div>
              ) : null}
              {detail.verifier_targets && detail.verifier_targets.length > 0 ? (
                <div className="space-y-2 rounded border border-border/60 bg-muted/30 px-3 py-2">
                  <div className="text-xs font-medium text-slate-300">
                    FOFA 目标 · 共 {detail.verifier_targets.length}
                    （成功 {detail.verifier_targets.filter((t) => t.status === 'success').length} · 失败{' '}
                    {detail.verifier_targets.filter((t) => t.status === 'fail').length} · 未测{' '}
                    {detail.verifier_targets.filter((t) => t.status === 'untested').length}）
                  </div>
                  {detail.verifier_fofa_query ? (
                    <div className="break-all font-mono text-xs text-slate-400">{detail.verifier_fofa_query}</div>
                  ) : null}
                  <div className="overflow-auto">
                    <table className="w-full min-w-[28rem] text-left text-xs">
                      <thead className="text-slate-500">
                        <tr>
                          <th className="py-1 pr-2 font-medium">状态</th>
                          <th className="py-1 pr-2 font-medium">目标</th>
                          <th className="py-1 pr-2 font-medium">标题</th>
                          <th className="py-1 font-medium">说明</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.verifier_targets.map((t, i) => (
                          <tr key={`${t.host}-${i}`} className="border-t border-border/40 align-top">
                            <td className="py-1.5 pr-2">
                              <Badge
                                variant={
                                  t.status === 'success'
                                    ? 'success'
                                    : t.status === 'fail'
                                      ? 'destructive'
                                      : 'outline'
                                }
                              >
                                {formatVerifierTargetStatus(t.status)}
                              </Badge>
                            </td>
                            <td className="py-1.5 pr-2 break-all text-slate-200">{t.host || '—'}</td>
                            <td className="py-1.5 pr-2 text-slate-400">{t.title || '—'}</td>
                            <td className="py-1.5 text-slate-400">{t.note || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
              {detail.verifier_status === 'verified' ? (
                <div className="space-y-2 rounded border border-emerald-900/50 bg-emerald-950/20 px-3 py-2">
                  <div className="text-xs font-medium text-emerald-300/90">互联网复现证据</div>
                  <div className="space-y-1 text-sm">
                    <div className="text-xs text-slate-400">FOFA 搜索语法</div>
                    <pre className="overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs text-slate-200">
                      {detail.verifier_fofa_query || '（未记录）'}
                    </pre>
                  </div>
                  <div className="space-y-1 text-sm">
                    <div className="text-xs text-slate-400">打通目标</div>
                    <div className="break-all text-slate-200">
                      {detail.verifier_verified_url || '（未记录 URL）'}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="text-xs text-slate-400">使用的 PoC</div>
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs text-slate-200">
                      {detail.verifier_poc || '（未记录对该目标发出的请求）'}
                    </pre>
                  </div>
                  <div className="space-y-1">
                    <div className="text-xs text-slate-400">实际响应</div>
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs text-slate-200">
                      {detail.verifier_response || '（未记录该目标的响应）'}
                    </pre>
                  </div>
                </div>
              ) : null}
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant={detail.tracking_status === 'submitted' ? 'default' : 'outline'}
                  disabled={marking}
                  onClick={() => markDetail(detail.tracking_status === 'submitted' ? 'none' : 'submitted')}
                >
                  {detail.tracking_status === 'submitted' ? '取消已提交' : '标记已提交'}
                </Button>
                <Button
                  size="sm"
                  variant={detail.tracking_status === 'ignored' ? 'default' : 'outline'}
                  disabled={marking}
                  onClick={() => markDetail(detail.tracking_status === 'ignored' ? 'none' : 'ignored')}
                >
                  {detail.tracking_status === 'ignored' ? '取消已忽略' : '标记已忽略'}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={
                    reportKind === 'advisory'
                      ? !detail.advisory_md
                      : reportKind === 'cve'
                        ? !detail.cve_json
                        : !detail.report_md
                  }
                  onClick={() => downloadReport(detail.id, reportKind)}
                >
                  <DownloadIcon data-icon="inline-start" />
                  {reportKind === 'advisory'
                    ? '下载 Advisory'
                    : reportKind === 'cve'
                      ? '下载 CVE JSON'
                      : '下载报告'}
                </Button>
                {detail.can_dynamic_verify || detail.dynamic_verify_queued ? (
                  <TooltipProvider delay={200}>
                    <Tooltip>
                      <TooltipTrigger render={<span className="inline-flex" />}>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={dynamicBusy || Boolean(detail.dynamic_verify_queued)}
                          onClick={() => startDynamicVerify()}
                        >
                          {dynamicBusy || detail.dynamic_verify_queued ? (
                            <Loader2Icon className="animate-spin" data-icon="inline-start" />
                          ) : null}
                          {detail.dynamic_verify_queued || dynamicBusy ? '追加验证中…' : '追加验证'}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-xs text-left leading-relaxed whitespace-normal">
                        {dynamicVerifyHint}
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                ) : null}
              </div>
              {dynamicError ? (
                <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {dynamicError}
                </div>
              ) : null}
              {detail.dynamic_verify_queued ? (
                <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                  已接续原审核轮次，正在
                  {detail.evidence_level === 'harness' ? '局部验证' : '静态'}
                  结论上追加验证。完成后证据等级会更新为动态验证或局部验证。
                </div>
              ) : null}
              {detail.submission_reason ? (
                <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                  <div className="text-xs text-slate-400">分层理由</div>
                  <div>{detail.submission_reason}</div>
                  {detail.root_cause_key ? (
                    <div className="mt-1 text-xs text-slate-400">根因键：{detail.root_cause_key}</div>
                  ) : null}
                </div>
              ) : null}
              {detail.merged_into_id ? (
                <div className="rounded border border-cyan-900/50 bg-cyan-950/30 px-3 py-2 text-sm text-cyan-200/90">
                  已并入主报告{' '}
                  <RelatedVulnLink id={detail.merged_into_id}>#{detail.merged_into_id}</RelatedVulnLink>
                </div>
              ) : null}
              {detail.merged_from_ids && detail.merged_from_ids.length > 0 ? (
                <div className="rounded border border-border/60 bg-muted/40 px-3 py-2 text-sm text-slate-300">
                  <div className="text-xs text-slate-400">已并入本报告的条目</div>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {detail.merged_from_ids.map((mid) => (
                      <RelatedVulnLink key={mid} id={mid}>
                        <span className="text-cyan-300">#{mid}</span>
                      </RelatedVulnLink>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  size="sm"
                  variant={reportKind === 'report' ? 'default' : 'outline'}
                  onClick={() => setReportKind('report')}
                >
                  中文报告
                </Button>
                <Button
                  size="sm"
                  variant={reportKind === 'advisory' ? 'default' : 'outline'}
                  onClick={() => setReportKind('advisory')}
                >
                  Advisory
                </Button>
                <Button
                  size="sm"
                  variant={reportKind === 'cve' ? 'default' : 'outline'}
                  onClick={() => setReportKind('cve')}
                >
                  CVE JSON
                </Button>
                {reportKind === 'advisory' ? (
                  <Button size="sm" variant="outline" disabled={!detail.advisory_md} onClick={() => copyAdvisory()}>
                    {advisoryCopied ? (
                      <CheckIcon data-icon="inline-start" />
                    ) : (
                      <CopyIcon data-icon="inline-start" />
                    )}
                    {advisoryCopied ? '已复制' : '复制到 GitHub'}
                  </Button>
                ) : null}
                {reportKind === 'cve' ? (
                  <Button size="sm" variant="outline" disabled={!detail.cve_json} onClick={() => copyCveJson()}>
                    {cveCopied ? (
                      <CheckIcon data-icon="inline-start" />
                    ) : (
                      <CopyIcon data-icon="inline-start" />
                    )}
                    {cveCopied ? '已复制' : '复制 CVE JSON'}
                  </Button>
                ) : null}
              </div>
              {reportKind === 'advisory' ? (
                <pre className="max-h-[min(70vh,48rem)] overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs leading-relaxed text-slate-200">
                  {detail.advisory_md || '暂无 Advisory。Worker / Reviewer 会写入 vulns/{id}/advisory.md。'}
                </pre>
              ) : reportKind === 'cve' ? (
                <pre className="max-h-[min(70vh,48rem)] overflow-auto whitespace-pre-wrap rounded bg-black/40 p-3 text-xs leading-relaxed text-slate-200">
                  {detail.cve_json ||
                    '暂无 CVE JSON。Worker / Reviewer 通过 ReadCveRecord / SetCveRecordField 写入 vulns/{id}/cve.json。'}
                </pre>
              ) : (
                <Suspense fallback={<div className="text-sm text-muted-foreground">加载报告…</div>}>
                  <MarkdownView content={detail.report_md || detail.source_sink || '_无报告_'} />
                </Suspense>
              )}
              {detail.http_request ? (
                <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.http_request}</pre>
              ) : null}
              {detail.poc_code ? (
                <div>
                  <div className="mb-1 text-xs text-slate-400">
                    {
                      'PoC：python poc.py -u <目标>；--proxy 设 HTTP 代理（空则直连）；RCE 可加 -c <命令>，有回显会打印'
                    }
                  </div>
                  <pre className="overflow-auto rounded bg-black/40 p-3 text-xs">{detail.poc_code}</pre>
                </div>
              ) : null}
              <VulnFollowUpPanel
                vulnId={detail.id}
                onReportApplied={async () => {
                  const next = await api.getVuln(detail.id)
                  setDetail(next)
                  onUpdated?.(next)
                }}
              />
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">加载报告…</div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
