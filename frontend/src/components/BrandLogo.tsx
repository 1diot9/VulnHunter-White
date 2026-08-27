import { cn } from '@/lib/utils'

export default function BrandLogo({ className }: { className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2 whitespace-nowrap', className)}>
      <img src="/logo.svg" alt="" width={28} height={28} className="size-7 rounded-md" />
      <span>VulnHunter-White</span>
    </span>
  )
}
