import { useState } from 'react'
import { CircleHelpIcon } from 'lucide-react'
import { useI18n } from '@/i18n'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { getBountyScopePremise, getBountyScopeRows, cn } from '@/lib/utils'

export function BountyScopeButton({ className }: { className?: string }) {
  const { t } = useI18n()
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
        {t('bounty.link')}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="flex max-h-[min(90vh,44rem)] w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl">
          <DialogHeader className="shrink-0 border-b border-border px-5 py-4 pr-12">
            <DialogTitle>{t('bounty.title')}</DialogTitle>
            <DialogDescription>{t('bounty.desc')}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto px-5 py-3">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-popover">
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="w-[11rem] py-2 pr-3 font-medium">{t('bounty.type')}</th>
                  <th className="w-[4.5rem] py-2 pr-3 font-medium">{t('bounty.include')}</th>
                  <th className="py-2 font-medium">{t('bounty.note')}</th>
                </tr>
              </thead>
              <tbody>
                {getBountyScopeRows().map((row) => (
                  <tr key={row.type} className="border-b border-border/60 last:border-0">
                    <td className="py-2 pr-3 align-top font-medium">{row.type}</td>
                    <td className="py-2 pr-3 align-top">
                      {row.included ? (
                        <Badge variant="success">{t('bounty.include')}</Badge>
                      ) : (
                        <Badge variant="destructive">{t('bounty.exclude')}</Badge>
                      )}
                    </td>
                    <td className="py-2 align-top text-muted-foreground">{row.note || t('common.dash')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{getBountyScopePremise()}</p>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
