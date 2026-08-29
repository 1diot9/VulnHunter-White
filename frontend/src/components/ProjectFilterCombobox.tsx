import { useMemo, useState } from 'react'
import { Combobox } from '@base-ui/react/combobox'
import { CheckIcon, ChevronDownIcon, SearchIcon } from 'lucide-react'
import type { ProjectName } from '../api'
import { cn } from '@/lib/utils'

const ALL_PROJECTS: ProjectOption = { id: null, name: '全部项目' }
/** 与选项行高对齐：text-sm 1.25rem + py-1 0.5rem = 1.75rem；含列表 p-1，默认露出 10 条后滚动 */
const LIST_MAX_HEIGHT_CLASS = 'max-h-[calc(10*1.75rem+0.5rem)]'

export type ProjectOption = {
  id: number | null
  name: string
}

function optionMatches(item: ProjectOption, query: string) {
  const q = query.trim().toLowerCase()
  if (!q) return true
  if (item.name.toLowerCase().includes(q)) return true
  if (item.id != null && String(item.id).includes(q)) return true
  return false
}

export default function ProjectFilterCombobox({
  projects,
  projectId,
  onProjectIdChange,
  className,
}: {
  projects: ProjectName[]
  projectId: number | undefined
  onProjectIdChange: (id: number | undefined) => void
  className?: string
}) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')

  const items = useMemo<ProjectOption[]>(
    () => [ALL_PROJECTS, ...projects.map((p) => ({ id: p.id, name: p.name || `项目 ${p.id}` }))],
    [projects],
  )

  const selected = useMemo(() => {
    if (projectId == null) return ALL_PROJECTS
    return items.find((item) => item.id === projectId) ?? { id: projectId, name: `项目 ${projectId}` }
  }, [items, projectId])

  return (
    <Combobox.Root
      items={items}
      value={selected}
      onValueChange={(next) => onProjectIdChange(next?.id ?? undefined)}
      itemToStringLabel={(item) => item.name}
      isItemEqualToValue={(a, b) => a.id === b.id}
      filter={optionMatches}
      inputValue={query}
      onInputValueChange={(value) => setQuery(value)}
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) setQuery('')
      }}
      autoHighlight
    >
      <Combobox.Trigger
        className={cn(
          "flex h-8 w-auto min-w-52 items-center justify-between gap-1.5 rounded-lg border border-input bg-transparent py-2 pr-2 pl-2.5 text-sm whitespace-nowrap transition-colors outline-none select-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30 dark:hover:bg-input/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
          className,
        )}
      >
                  <span className="min-w-0 flex-1 truncate text-left">
                    {selected.id != null ? `#${selected.id} ${selected.name}` : selected.name}
                  </span>
        <Combobox.Icon className="flex shrink-0">
          <ChevronDownIcon className="pointer-events-none size-4 text-muted-foreground" />
        </Combobox.Icon>
      </Combobox.Trigger>
      <Combobox.Portal>
        <Combobox.Positioner className="isolate z-50" sideOffset={4} align="start">
          <Combobox.Popup className="flex w-(--anchor-width) min-w-52 origin-(--transform-origin) flex-col overflow-hidden rounded-lg bg-popover text-popover-foreground shadow-md ring-1 ring-foreground/10 duration-100 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95">
            <div className="border-b border-border p-1.5">
              <div className="relative">
                <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Combobox.Input
                  className="h-8 w-full rounded-md border border-input bg-transparent py-1 pr-2 pl-7 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                  placeholder="搜索项目名称或编号…"
                  aria-label="搜索项目"
                />
              </div>
            </div>
            <Combobox.Empty className="px-2 py-6 text-center text-sm text-muted-foreground">
              无匹配项目
            </Combobox.Empty>
            <Combobox.List className={cn('overflow-x-hidden overflow-y-auto overscroll-contain p-1 outline-none', LIST_MAX_HEIGHT_CLASS)}>
              {(item: ProjectOption) => (
                <Combobox.Item
                  key={item.id == null ? '__all__' : item.id}
                  value={item}
                  className="relative flex min-h-7 w-full cursor-default items-center gap-1.5 rounded-md py-1 pr-8 pl-1.5 text-sm outline-hidden select-none data-highlighted:bg-accent data-highlighted:text-accent-foreground"
                >
                  <span className="min-w-0 flex-1 truncate">
                    {item.id != null ? `#${item.id} ${item.name}` : item.name}
                  </span>
                  <Combobox.ItemIndicator className="pointer-events-none absolute right-2 flex size-4 items-center justify-center">
                    <CheckIcon className="size-4" />
                  </Combobox.ItemIndicator>
                </Combobox.Item>
              )}
            </Combobox.List>
          </Combobox.Popup>
        </Combobox.Positioner>
      </Combobox.Portal>
    </Combobox.Root>
  )
}
