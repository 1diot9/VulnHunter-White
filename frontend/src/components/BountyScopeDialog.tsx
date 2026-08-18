import { useState } from 'react'
import { CircleHelpIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { BOUNTY_SCOPE_PREMISE, BOUNTY_SCOPE_ROWS, cn } from '@/lib/utils'

export function BountyScopeButton({ className }: { className?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button
        type="button"
        variant="link"
        size="sm"
        className={cn('h-auto gap-1 px-0 text-xs text-muted-foreground hover:text-foreground', className)}
        onClick={() => setOpen(true)}
      >
        <CircleHelpIcon className="size-3.5" />
        收录范围
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>赏金模式收录范围</DialogTitle>
            <DialogDescription>只收录默认可利用、能造成实际危害的问题。下表为完整对照。</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto px-5 py-3">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-popover">
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="w-[11rem] py-2 pr-3 font-medium">类型</th>
                  <th className="w-[4.5rem] py-2 pr-3 font-medium">收录</th>
                  <th className="py-2 font-medium">说明</th>
                </tr>
              </thead>
              <tbody>
                {BOUNTY_SCOPE_ROWS.map((row) => (
                  <tr key={row.type} className="border-b border-border/60 last:border-0">
                    <td className="py-2 pr-3 align-top font-medium">{row.type}</td>
                    <td className="py-2 pr-3 align-top">
                      {row.included ? (
                        <Badge variant="success">收录</Badge>
                      ) : (
                        <Badge variant="destructive">不收录</Badge>
                      )}
                    </td>
                    <td className="py-2 align-top text-muted-foreground">{row.note || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{BOUNTY_SCOPE_PREMISE}</p>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
