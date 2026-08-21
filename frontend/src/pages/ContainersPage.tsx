import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2Icon, RefreshCw, Square, Trash2 } from 'lucide-react'
import {
  api,
  type DockerContainer,
  type DockerImage,
  type DockerImagePruneResult,
  type DockerImageUsage,
} from '../api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  containerStatusBadgeVariant,
  formatBytes,
  formatDateTime,
} from '../lib/utils'
import { startVisibilityPoll } from '../lib/visibilityPoll'

const KIND_LABEL: Record<string, string> = {
  lab: '靶场',
  sidecar: '依赖容器',
  sandbox: '沙箱',
  other: '其他',
  dependency: '拉取依赖',
}

function kindLabel(kind: string | null | undefined): string {
  if (!kind) return '—'
  return KIND_LABEL[kind] || kind
}

function summarizeBatchErrors(
  results: Array<{ id: string; error: string | null }>,
  slice = 12,
): string | null {
  const failed = results.filter((r) => r.error)
  if (failed.length === 0) return null
  return `部分失败：${failed.map((r) => `${r.id.slice(0, slice)} (${r.error})`).join('；')}`
}

function usageFromImages(images: DockerImage[]): DockerImageUsage {
  const total_bytes = images.reduce((sum, img) => sum + (img.size_bytes || 0), 0)
  return {
    image_count: images.length,
    dangling_count: images.filter((img) => img.dangling).length,
    total_bytes,
    total_mb: Math.round((total_bytes / (1024 * 1024)) * 100) / 100,
    total_gb: Math.round((total_bytes / 1024 ** 3) * 100) / 100,
  }
}

function TableLoading({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-3" role="status" aria-live="polite" aria-busy="true">
      <div className="flex items-center gap-2 text-sm">
        <Loader2Icon className="size-4 animate-spin" aria-hidden />
        {label}
      </div>
      <div className="w-56 space-y-2">
        <div className="h-2.5 w-[88%] animate-pulse rounded bg-muted" />
        <div className="h-2.5 w-[64%] animate-pulse rounded bg-muted" />
        <div className="h-2.5 w-[76%] animate-pulse rounded bg-muted" />
      </div>
    </div>
  )
}

export default function ContainersPage() {
  const [containers, setContainers] = useState<DockerContainer[]>([])
  const [images, setImages] = useState<DockerImage[]>([])
  const [usage, setUsage] = useState<DockerImageUsage | null>(null)
  const [runningOnly, setRunningOnly] = useState(true)
  const [selectedContainers, setSelectedContainers] = useState<Set<string>>(new Set())
  const [selectedImages, setSelectedImages] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pruneResult, setPruneResult] = useState<DockerImagePruneResult | null>(null)
  const [containersReady, setContainersReady] = useState(false)
  const [imagesReady, setImagesReady] = useState(false)
  const refreshGen = useRef(0)

  const refresh = useCallback(async () => {
    const gen = ++refreshGen.current
    try {
      const list = await api.listContainers(runningOnly)
      if (gen !== refreshGen.current) return
      setContainers(list)
      setContainersReady(true)
      setSelectedContainers((prev) => {
        const ids = new Set(list.map((c) => c.id))
        return new Set([...prev].filter((id) => ids.has(id)))
      })
    } catch (err) {
      if (gen !== refreshGen.current) return
      setContainersReady(true)
      setImagesReady(true)
      setError(String(err))
      return
    }
    try {
      const imageList = await api.listDockerImages()
      if (gen !== refreshGen.current) return
      setImages(imageList)
      setUsage(usageFromImages(imageList))
      setImagesReady(true)
      setSelectedImages((prev) => {
        const ids = new Set(imageList.map((img) => img.id))
        return new Set([...prev].filter((id) => ids.has(id)))
      })
      setError(null)
    } catch (err) {
      if (gen !== refreshGen.current) return
      setImagesReady(true)
      setError(String(err))
    }
  }, [runningOnly])

  useEffect(() => {
    setContainersReady(false)
    const stop = startVisibilityPoll(() => refresh(), 5000)
    return () => {
      refreshGen.current += 1
      stop()
    }
  }, [refresh])

  const runningCount = useMemo(
    () => containers.filter((c) => c.status === 'running').length,
    [containers],
  )
  const allContainersSelected =
    containers.length > 0 && containers.every((c) => selectedContainers.has(c.id))
  const deletableImages = useMemo(() => images.filter((img) => img.deletable), [images])
  const allImagesSelected =
    deletableImages.length > 0 && deletableImages.every((img) => selectedImages.has(img.id))

  const toggleAllContainers = (checked: boolean) => {
    setSelectedContainers(checked ? new Set(containers.map((c) => c.id)) : new Set())
  }

  const toggleOneContainer = (id: string, checked: boolean) => {
    setSelectedContainers((prev) => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
  }

  const toggleAllImages = (checked: boolean) => {
    setSelectedImages(checked ? new Set(deletableImages.map((img) => img.id)) : new Set())
  }

  const toggleOneImage = (id: string, checked: boolean) => {
    setSelectedImages((prev) => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
  }

  const stopOne = async (id: string) => {
    setBusy(true)
    setError(null)
    try {
      await api.stopContainer(id)
      await refresh()
      setSelectedContainers((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const startOne = async (id: string) => {
    setBusy(true)
    setError(null)
    try {
      await api.startContainer(id)
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const stopSelected = async () => {
    const ids = [...selectedContainers]
    if (ids.length === 0) return
    setBusy(true)
    setError(null)
    try {
      const { results } = await api.stopContainers(ids)
      const message = summarizeBatchErrors(results)
      if (message) setError(message)
      setSelectedContainers(new Set())
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const startSelected = async () => {
    const ids = [...selectedContainers]
    if (ids.length === 0) return
    setBusy(true)
    setError(null)
    try {
      const { results } = await api.startContainers(ids)
      const message = summarizeBatchErrors(results)
      if (message) setError(message)
      setSelectedContainers(new Set())
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const stopAllRunning = async () => {
    const ids = containers.filter((c) => c.status === 'running').map((c) => c.id)
    if (ids.length === 0) return
    setBusy(true)
    setError(null)
    try {
      await api.stopContainers(ids)
      setSelectedContainers(new Set())
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const removeImagesByIds = async (ids: string[]) => {
    if (ids.length === 0) return
    setBusy(true)
    setError(null)
    try {
      const { results } = await api.removeDockerImages(ids)
      const message = summarizeBatchErrors(results)
      if (message) setError(message)
      setSelectedImages(new Set())
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  const removeSelectedImages = async () => {
    const ids = images.filter((img) => selectedImages.has(img.id) && img.deletable).map((img) => img.id)
    if (ids.length === 0) return
    if (!window.confirm(`删除所选 ${ids.length} 个未使用的靶场/沙箱镜像？官方依赖镜像不会删除。`)) return
    await removeImagesByIds(ids)
  }

  const removeOneImage = async (id: string) => {
    if (!window.confirm('删除该未使用的靶场/沙箱镜像？')) return
    await removeImagesByIds([id])
  }

  const pruneImages = async () => {
    if (
      !window.confirm(
        '清理未使用的自建靶场镜像，并删除已停止的本平台容器？\n运行中的容器及其镜像不受影响；沙箱镜像和官方 mysql/redis 等依赖需手动处理。',
      )
    ) {
      return
    }
    setBusy(true)
    setError(null)
    setPruneResult(null)
    try {
      const result = await api.pruneDockerImages(true)
      setPruneResult(result)
      await refresh()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">容器与镜像</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            本平台搭建的靶场容器、局部验证沙箱，以及对应镜像（含拉取的官方依赖）
            {containersReady
              ? runningOnly
                ? ` · 运行中 ${runningCount}`
                : ` · 共 ${containers.length}，运行中 ${runningCount}`
              : ' · 加载中…'}
            {imagesReady && usage
              ? ` · 镜像 ${usage.image_count} 个 / ${usage.total_gb} GB（悬空 ${usage.dangling_count}）`
              : ''}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant={runningOnly ? 'default' : 'outline'} size="sm" onClick={() => setRunningOnly(true)}>
            仅运行中
          </Button>
          <Button variant={!runningOnly ? 'default' : 'outline'} size="sm" onClick={() => setRunningOnly(false)}>
            全部
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => {
              refresh().catch((e) => setError(String(e)))
            }}
          >
            <RefreshCw className={`size-3.5 ${containersReady ? '' : 'animate-spin'}`} />
            刷新
          </Button>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => void pruneImages()}>
            <Trash2 className="size-3.5" />
            清理未使用镜像
          </Button>
        </div>
      </div>

      {pruneResult && !pruneResult.skipped && (
        <p className="text-sm text-emerald-400">
          清理完成：删除 {pruneResult.images_deleted} 个镜像 · 已停容器 {pruneResult.containers_removed} · 释放{' '}
          {pruneResult.freed_mb} MB
          {pruneResult.errors.length > 0 ? `（部分错误：${pruneResult.errors.join('；')}）` : ''}
        </p>
      )}

      {error && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">容器列表</CardTitle>
          <CardDescription>可单停、启动或勾选后批量操作；只展示 VulnHunter 靶场与沙箱</CardDescription>
          <CardAction>
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="outline" disabled={busy || selectedContainers.size === 0} onClick={() => void startSelected()}>
                启动所选 ({selectedContainers.size})
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={busy || selectedContainers.size === 0}
                onClick={() => void stopSelected()}
              >
                <Square className="size-3.5" />
                停止所选 ({selectedContainers.size})
              </Button>
              <Button size="sm" variant="outline" disabled={busy || runningCount === 0} onClick={() => void stopAllRunning()}>
                停止全部运行中
              </Button>
            </div>
          </CardAction>
        </CardHeader>
        <CardContent className="p-0">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-10 pl-4">
                  <Checkbox
                    checked={allContainersSelected}
                    onCheckedChange={(v) => toggleAllContainers(v === true)}
                    disabled={containers.length === 0}
                    aria-label="全选容器"
                  />
                </TableHead>
                <TableHead className="w-28">ID</TableHead>
                <TableHead>名称</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-24">类型</TableHead>
                <TableHead className="w-36">项目</TableHead>
                <TableHead>镜像</TableHead>
                <TableHead className="w-40">端口</TableHead>
                <TableHead className="w-28 text-right pr-4">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!containersReady ? (
                <TableRow>
                  <TableCell colSpan={9} className="py-10 text-center text-muted-foreground">
                    <TableLoading label="加载容器…" />
                  </TableCell>
                </TableRow>
              ) : containers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="py-10 text-center text-muted-foreground">
                    {runningOnly ? '当前没有运行中的 VulnHunter 容器' : '未发现本平台容器'}
                  </TableCell>
                </TableRow>
              ) : null}
              {containersReady &&
                containers.map((c) => {
                const portsText = c.ports.join(', ')
                return (
                  <TableRow key={c.id}>
                    <TableCell className="pl-4">
                      <Checkbox
                        checked={selectedContainers.has(c.id)}
                        onCheckedChange={(v) => toggleOneContainer(c.id, v === true)}
                        aria-label={`选择 ${c.name}`}
                      />
                    </TableCell>
                    <TableCell className="font-mono text-xs">{c.short_id}</TableCell>
                    <TableCell className="max-w-0 truncate font-mono text-sm" title={c.name}>
                      {c.name}
                    </TableCell>
                    <TableCell>
                      <Badge variant={containerStatusBadgeVariant(c.status)}>{c.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{kindLabel(c.kind)}</TableCell>
                    <TableCell className="max-w-0 truncate">
                      {c.project_id ? (
                        <Link to={`/projects/${c.project_id}`} className="text-sm text-primary hover:underline" title={c.project_name || `#${c.project_id}`}>
                          {c.project_name || `#${c.project_id}`}
                        </Link>
                      ) : (
                        <span className="text-sm text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-0 truncate text-xs text-muted-foreground" title={c.image}>
                      {c.image}
                    </TableCell>
                    <TableCell className="max-w-0 truncate font-mono text-xs" title={portsText || undefined}>
                      {c.ports.length > 0 ? portsText : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="pr-4 text-right whitespace-nowrap">
                      {c.status === 'running' ? (
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void stopOne(c.id)}>
                          停止
                        </Button>
                      ) : (
                        <Button size="sm" variant="outline" disabled={busy} onClick={() => void startOne(c.id)}>
                          启动
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">镜像列表</CardTitle>
          <CardDescription>
            自建靶场镜像、沙箱镜像，以及仍被本平台容器使用的拉取依赖；官方依赖不可在此删除
          </CardDescription>
          <CardAction>
            <Button
              size="sm"
              variant="destructive"
              disabled={busy || selectedImages.size === 0}
              onClick={() => void removeSelectedImages()}
            >
              <Trash2 className="size-3.5" />
              删除所选 ({selectedImages.size})
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="p-0">
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-10 pl-4">
                  <Checkbox
                    checked={allImagesSelected}
                    onCheckedChange={(v) => toggleAllImages(v === true)}
                    disabled={deletableImages.length === 0}
                    aria-label="全选可删除镜像"
                  />
                </TableHead>
                <TableHead>镜像</TableHead>
                <TableHead className="w-24">类型</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-36">项目</TableHead>
                <TableHead className="w-24">体积</TableHead>
                <TableHead className="w-44">创建时间</TableHead>
                <TableHead className="w-20 text-right pr-4">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!imagesReady ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-10 text-center text-muted-foreground">
                    <TableLoading label="加载镜像…" />
                  </TableCell>
                </TableRow>
              ) : images.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-10 text-center text-muted-foreground">
                    未发现本平台相关镜像
                  </TableCell>
                </TableRow>
              ) : (
                images.map((img) => (
                <TableRow key={img.id}>
                  <TableCell className="pl-4">
                    <Checkbox
                      checked={selectedImages.has(img.id)}
                      onCheckedChange={(v) => toggleOneImage(img.id, v === true)}
                      disabled={!img.deletable}
                      aria-label={`选择 ${img.label}`}
                    />
                  </TableCell>
                  <TableCell className="max-w-0 truncate font-mono text-xs" title={img.tags.join(', ') || img.label}>
                    {img.label}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{kindLabel(img.kind)}</TableCell>
                  <TableCell>
                    <Badge variant={img.in_use ? 'info' : img.dangling ? 'warning' : 'secondary'}>
                      {img.in_use ? '使用中' : img.dangling ? '悬空' : '未使用'}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-0 truncate">
                    {img.project_id ? (
                      <Link to={`/projects/${img.project_id}`} className="text-sm text-primary hover:underline">
                        {img.project_name || `#${img.project_id}`}
                      </Link>
                    ) : (
                      <span className="text-sm text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatBytes(img.size_bytes)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTime(img.created)}</TableCell>
                  <TableCell className="pr-4 text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy || !img.deletable}
                      onClick={() => void removeOneImage(img.id)}
                    >
                      删除
                    </Button>
                  </TableCell>
                </TableRow>
              ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
