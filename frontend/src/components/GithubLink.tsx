import type { MouseEvent } from 'react'
import { ExternalLinkIcon } from 'lucide-react'
import { useI18n } from '@/i18n'
import { buttonVariants } from '@/components/ui/button'
import { githubRepoHref, githubRepoLabel, type ProjectGithubFields } from '@/lib/github'
import { cn } from '@/lib/utils'

export function GithubLink({
  project,
  variant = 'inline',
  className,
}: {
  project: ProjectGithubFields
  variant?: 'inline' | 'button'
  className?: string
}) {
  const { t } = useI18n()
  const href = githubRepoHref(project)
  if (!href) return null
  const label = githubRepoLabel(project) || 'GitHub'
  const common = {
    href,
    target: '_blank' as const,
    rel: 'noopener noreferrer',
    title: t('comp.github.open', { label }),
    onClick: (e: MouseEvent) => e.stopPropagation(),
  }
  if (variant === 'button') {
    return (
      <a {...common} className={cn(buttonVariants({ variant: 'outline', size: 'sm' }), className)}>
        <ExternalLinkIcon data-icon="inline-start" />
        GitHub
      </a>
    )
  }
  return (
    <a
      {...common}
      className={cn('inline-flex max-w-full items-center gap-0.5 hover:underline', className)}
    >
      <span className="truncate">{label}</span>
      <ExternalLinkIcon className="size-3 shrink-0" />
    </a>
  )
}
