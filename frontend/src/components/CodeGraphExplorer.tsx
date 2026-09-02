import { useEffect, useState } from 'react'
import { api, type CodeIntelSymbol } from '../api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'

function loc(item: CodeIntelSymbol): string {
  const file = item.file || ''
  if (file && item.line != null) return `${file}:${item.line}`
  return file
}

function SymbolList({
  items,
  empty,
  onPick,
}: {
  items: CodeIntelSymbol[]
  empty: string
  onPick: (item: CodeIntelSymbol) => void
}) {
  if (!items.length) {
    return <p className="px-1 py-2 text-xs text-muted-foreground">{empty}</p>
  }
  return (
    <ul className="min-h-0 flex-1 overflow-auto">
      {items.map((item, idx) => (
        <li key={`${item.name}-${item.file || ''}-${item.line ?? idx}`}>
          <button
            type="button"
            className="flex w-full flex-col items-start gap-0.5 rounded-md px-2 py-1.5 text-left hover:bg-muted/70"
            onClick={() => onPick(item)}
          >
            <span className="font-mono text-xs text-foreground">{item.name}</span>
            <span className="text-[11px] text-muted-foreground">
              {loc(item) || item.kind || '—'}
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}

export function CodeGraphExplorer({
  projectId,
  open,
  onOpenChange,
}: {
  projectId: number
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [query, setQuery] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [hits, setHits] = useState<CodeIntelSymbol[]>([])
  const [selected, setSelected] = useState<CodeIntelSymbol | null>(null)
  const [callers, setCallers] = useState<CodeIntelSymbol[]>([])
  const [callees, setCallees] = useState<CodeIntelSymbol[]>([])

  useEffect(() => {
    if (!open) return
    setQuery('')
    setError('')
    setHits([])
    setSelected(null)
    setCallers([])
    setCallees([])
  }, [open, projectId])

  const search = () => {
    const q = query.trim()
    if (!q) return
    setBusy(true)
    setError('')
    void api
      .queryCodeIntelSymbols(projectId, q)
      .then((out) => {
        if (!out.ok) {
          setHits([])
          setError(out.error || '查询失败')
          return
        }
        setHits(out.items || [])
      })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => setBusy(false))
  }

  const inspect = (item: CodeIntelSymbol) => {
    setSelected(item)
    setBusy(true)
    setError('')
    void Promise.all([
      api.queryCodeIntelCallers(projectId, item.name),
      api.queryCodeIntelCallees(projectId, item.name),
    ])
      .then(([from, to]) => {
        if (!from.ok) {
          setError(from.error || '查询调用方失败')
          setCallers([])
        } else {
          setCallers(from.callers || [])
        }
        if (!to.ok) {
          setError((prev) => prev || to.error || '查询被调失败')
          setCallees([])
        } else {
          setCallees(to.callees || [])
        }
      })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)))
      .finally(() => setBusy(false))
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-4xl">
        <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
          <DialogTitle>调用图浏览</DialogTitle>
          <DialogDescription>
            当前 CodeGraph 发行版没有官方图浏览器，这里用同一套索引查符号和调用关系。
          </DialogDescription>
        </DialogHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-3 px-5 py-3">
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              search()
            }}
          >
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="符号名，例如 login / Runtime.exec"
              disabled={busy}
            />
            <Button type="submit" size="sm" disabled={busy || !query.trim()}>
              {busy ? '查询…' : '查询'}
            </Button>
          </form>
          {error ? <p className="text-xs text-red-300">{error}</p> : null}
          <div className="grid min-h-0 flex-1 gap-3 md:grid-cols-3">
            <section className="flex min-h-0 flex-col rounded-lg border border-border/80">
              <h3 className="shrink-0 border-b border-border px-2 py-1.5 text-xs text-muted-foreground">
                符号 {hits.length ? `(${hits.length})` : ''}
              </h3>
              <SymbolList items={hits} empty="输入符号名后查询" onPick={inspect} />
            </section>
            <section className="flex min-h-0 flex-col rounded-lg border border-border/80">
              <h3 className="shrink-0 border-b border-border px-2 py-1.5 text-xs text-muted-foreground">
                调用方 {selected ? `(${callers.length})` : ''}
              </h3>
              <SymbolList
                items={callers}
                empty={selected ? '没有调用方' : '先选一个符号'}
                onPick={inspect}
              />
            </section>
            <section className="flex min-h-0 flex-col rounded-lg border border-border/80">
              <h3 className="shrink-0 border-b border-border px-2 py-1.5 text-xs text-muted-foreground">
                被调 {selected ? `(${callees.length})` : ''}
              </h3>
              <SymbolList
                items={callees}
                empty={selected ? '没有被调' : '先选一个符号'}
                onPick={inspect}
              />
            </section>
          </div>
          {selected ? (
            <p className="shrink-0 truncate font-mono text-[11px] text-muted-foreground">
              当前：{selected.name}
              {loc(selected) ? ` · ${loc(selected)}` : ''}
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
